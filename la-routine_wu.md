# la routine - hackropole intro 2026

The sample for this reverse engineering challenge can be found on [Hacropole](https://hackropole.fr/fr/challenges/reverse/fcsc2026-reverse-la-routine/).
In this write-up, we will use a GDB script to solve it.
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image1.png)

---

## Basic static / dynamic analysis

Running `file` and `checksec` reveals that the binary is not stripped and PIE is disabled.

A review of `strings` yielded no interesting results, and running the binary with `strace` or `ltrace` did not provide any useful insights.
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image2.png)

When executing the binary, it prompts for user input and then prints an output.
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image5.png)

---

## Static analysis

Using Binary Ninja, we can easily locate `main.main` since the binary is not stripped.

Because Go is a high-level language, the binary includes a significant amount of initialization and garbage collection overhead. Furthermore, all necessary libraries are statically linked within the compiled binary.

![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image3.png)

---

At the end of the `main.main` function, we find an input scan from `stdin`, followed by a conditional check and a print statement, confirming our observations from the initial dynamic analysis.
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image15.png)

---

Inside the `main.check` function, we analyze how and why the function returns.
There are three distinct return paths:
- A return triggered if an error occurs.
- A return triggered if the flag length is not a multiple of 4.
- A final return reached once the loop completes successfully.
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image6.png)

---

Let's focus on the primary verification logic.
The application calls `internal/bytealg.Compare`, passing `main.expected` and an unknown buffer as arguments.

![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image16.png)
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image9.png)

---

Now for the core algorithm: the function appears to transform our input before comparing it to the `main.expected` array we identified earlier.

![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image17.png)

Let's solve this problem dynamically.

---

# dynamic analysis

For the dynamic analysis, we will use a GDB script.

We have identified a few functions that might be useful:
1) a function to calculate pie address (though it is redundant here since PIE is disabled) .
```python
def pie_calc_address(binja_address):  
   # exe_base = 0x555555554000  
   exe_base = 0x400000  
   binja_base = 0x400000  
   offset = binja_address - binja_base  
   exe_address = exe_base + offset  
   return hex(exe_address)
```

2) functions to break and watch.
```python
def pie_break(binja_address):  
   exe_address = pie_calc_address(binja_address)  
   gdb.execute(f"break *{exe_address}")
   gdb.execute("commands $bpnum\nsilent\nend")
   
def pie_watch(binja_address):  
   exe_address = pie_calc_address(binja_address)  
   gdb.execute(f"watch *{exe_address}")
```

3) A function to print memory content at a specific address and parse code.
```python
def pie_print(binja_address, message):  
   exe_address = pie_calc_address(binja_address)  
   tokens = re.findall(r'\{\*?([\$\w\+\-\*\d\s]+),\s*(%\w+)\}', message)  
   fmt = re.sub(r'\{\*?[\$\w\+\-\*\d\s]+,\s*%\w+\}', lambda m: re.search(r'%\w+', m.group()).group(), message)  
   gdb_args = ", ".join(f"*(char*)({expr})" if m.startswith('{*') else expr.replace('$', '$')  
                        for m, (expr, _) in zip(re.findall(r'\{[^}]+\}', message), tokens))  
   if gdb_args:  
       gdb.execute(f'dprintf *{exe_address}, "{fmt}\\n", {gdb_args}')  
   else:  
       gdb.execute(f'dprintf *{exe_address}, "{fmt}\\n"')
      
def binary_ninja_dbg(code):  
   lines = code.split("\n")  
   for line in lines:  
       if len(line.split()) <= 1: continue  
       address, sep, code = line.partition(" ")  
       address = int(address, 16)  
       print(address, sep + code)  
       pie_print(address, sep + code)
```

---

Let's set a breakpoint at the compare function.
```python
# gdb script  
python pie_break(0x004a698d) # compare function break
  
python pie_print(0x004a698a, "0x004a698a rax = {$rax, %s}")  # print expected
python pie_print(0x004a698a, "0x004a698a rdi = {$rdi, %s}")  # print our transformed flag
python pie_print(0x004a698a, "0x004a698a call internal/bytealg.Compare")  
run <<< FCSC{fake_flag.}
```
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image10.png)
![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image12.png|541)

We discovered that the first five characters of the transformed input match the prefix of the expected flag (`FSCS{`).

This indicates that the algorithm processes and transforms our input character by character, independently. Consequently, we can brute-force the flag one character at a time by comparing the output of each attempt against the `main.expected` array.

---

We can retrieve the flag using the following function:
```python
def brute_force():  
   n = 48  
   res = ['.']*n  
   ind = 0  
   pie_break(0x004a698d)  
  
   while (ind < n):  
       for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}_!":  
           res[ind] = c  
           gdb.execute(f"run <<< {"".join(res)}", to_string=True)  
  
           inferior = gdb.selected_inferior()  
           expected_address = int(gdb.parse_and_eval("$rax"))  
           expected_len = int(gdb.parse_and_eval("$rbx"))  
           expected = inferior.read_memory(expected_address, expected_len).tobytes().decode('utf-8', errors='ignore  
')  
           flag_address = int(gdb.parse_and_eval("$rdi"))  
           flag_len = int(gdb.parse_and_eval("$rsi"))  
           flag = inferior.read_memory(flag_address, flag_len).tobytes().decode('utf-8', errors='ignore')  
  
           if expected[ind] == flag[ind]:  
               print("".join(res))  
               ind += 1  
               break
```

![image](https://raw.githubusercontent.com/Nardre/la-routine_images/main/image14.png)

FCSC{GoLanG_......................._P4TTerNs!!!}

---

Here is the full script.
```python
set sysroot /
set disable-randomization on
set confirm off
set print thread-events off
set verbose off
set debuginfod enabled off
set print inferior-events off
set print thread-events off

file ./la-routine

# python function
python
import re

def pie_calc_address(binja_address):
    # exe_base = 0x555555554000
    exe_base = 0x400000
    binja_base = 0x400000
    offset = binja_address - binja_base
    exe_address = exe_base + offset
    return hex(exe_address)

def pie_break(binja_address):
    exe_address = pie_calc_address(binja_address)
    gdb.execute(f"break *{exe_address}")
    gdb.execute("commands $bpnum\nsilent\nend")

def pie_print(binja_address, message):
    exe_address = pie_calc_address(binja_address)
    tokens = re.findall(r'\{\*?([\$\w\+\-\*\d\s]+),\s*(%\w+)\}', message)
    fmt = re.sub(r'\{\*?[\$\w\+\-\*\d\s]+,\s*%\w+\}', lambda m: re.search(r'%\w+', m.group()).group(), message)
    gdb_args = ", ".join(f"*(char*)({expr})" if m.startswith('{*') else expr.replace('$', '$')
                         for m, (expr, _) in zip(re.findall(r'\{[^}]+\}', message), tokens))
    if gdb_args:
        gdb.execute(f'dprintf *{exe_address}, "{fmt}\\n", {gdb_args}')
    else:
        gdb.execute(f'dprintf *{exe_address}, "{fmt}\\n"')

def pie_watch(binja_address):
    exe_address = pie_calc_address(binja_address)
    gdb.execute(f"watch *{exe_address}")

def binary_ninja_dbg(code):
    lines = code.split("\n")
    for line in lines:
        if len(line.split()) <= 1: continue
        address, sep, code = line.partition(" ")
        address = int(address, 16)
        print(address, sep + code)
        pie_print(address, sep + code)

def brute_force():
    n = 48
    res = ['.']*n
    ind = 0
    pie_break(0x004a698d)

    while (ind < n):
        for c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890{}_!":
            res[ind] = c
            gdb.execute(f"run <<< {"".join(res)}", to_string=True)

            inferior = gdb.selected_inferior()
            expected_address = int(gdb.parse_and_eval("$rax"))
            expected_len = int(gdb.parse_and_eval("$rbx"))
            expected = inferior.read_memory(expected_address, expected_len).tobytes().decode('utf-8', errors='ignore')
            flag_address = int(gdb.parse_and_eval("$rdi"))
            flag_len = int(gdb.parse_and_eval("$rsi"))
            flag = inferior.read_memory(flag_address, flag_len).tobytes().decode('utf-8', errors='ignore')

            if expected[ind] == flag[ind]:
                print("".join(res))
                ind += 1
                break
end

# gdb script
# python pie_break(0x004a698d)

# python pie_print(0x004a698a, "0x004a698a rax = {$rax, %s}")
# python pie_print(0x004a698a, "0x004a698a rdi = {$rdi, %s}")
# python pie_print(0x004a698a, "0x004a698a call internal/bytealg.Compare")
# run <<< FCSC{fake_flag.}
python brute_force()
```

To use it:

```bash
chmod +x la-routine
gdb --q --nx -x solve.gdb
```

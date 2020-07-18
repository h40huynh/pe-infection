# PE-INFECTION-DECRYPTOR

## GIỚI THIỆU

Chương trình giúp lây nhiễm shellcode vào file thực thi win32. Đoạn shellcode chỉ thực thi khi ở máy thật và không ở chế độ debug. Các kỹ thuật sử dụng:

- Anti-VM: Kiểm tra CPUID với eax = 1.
- Anti-VM: Kiểm tra Hypervisor Brand với CPUID khi eax = 0x40000000.
- Anti-Debugging: Kiểm tra biến PEB.BeingDebugged.

## Sử dụng

Clone project:

```
git clone https://github.com/h40huynh/PE-infection-decryptor.git
```

Chạy file setup.bat hoặc complie code với Mingw 32bit:

```
gcc src/*c -o bin/peinfection.exe
```

Sử dụng:

```
peinfection <path>
```

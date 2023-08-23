# windriver
Example of simple Windows driver compiled on Linux using Mingw.  Performs I/O to BIOS POST port 0x80.

**Compile the driver testdrv.sys from source testdrv.c**

```c
/*
  Windows device driver minimal example:
  Handles RW single byte on BIOS POST I/O port 0x80

  Compile on Linux using mingw:
  /usr/bin/x86_64-w64-mingw32-gcc -Wl,-L"/usr/x86_64-w64-mingw32/lib/" -I"/usr/x86_64-w64-mingw32/include/ddk" -Wall -m64 -shared -Wl,--subsystem,native -Wl,--image-base,0x10000 -Wl,--file-alignment,0x1000 -Wl,--section-alignment,0x1000 -Wl,--entry,DriverEntry@8 -Wl,--stack,0x40000 -Wl,--dynamicbase -Wl,--nxcompat -nostartfiles -nostdlib -o testdrv.sys testdrv.c -lntoskrnl -lhal
*/

#include <ntddk.h>
#include <wdm.h>

#define DEVNAME L"\\Device\\TestDriver"
#define SYMLINK L"\\??\\TestDriver"

void byte2hex(void *byte, int bytelen, char *hex, int hexlen);
void hex2byte(void *byte, int bytelen, char *hex, int hexlen);
NTSTATUS TestDriverCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS TestDriverRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS TestDriverWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void Unload(_In_ PDRIVER_OBJECT DriverObject);

DRIVER_INITIALIZE DriverEntry;

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
   UNREFERENCED_PARAMETER(DriverObject);
   UNREFERENCED_PARAMETER(RegistryPath);
   UNICODE_STRING devName = RTL_CONSTANT_STRING(DEVNAME);
   PDEVICE_OBJECT DeviceObject;
   NTSTATUS status;

   status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
   if(!NT_SUCCESS(status)) { return status; }

   UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK);
   status = IoCreateSymbolicLink(&symLink, &devName);
   if(!NT_SUCCESS(status)) { IoDeleteDevice(DeviceObject); return status; }

   DeviceObject->Flags |= DO_BUFFERED_IO;

   DriverObject->MajorFunction[IRP_MJ_CREATE] = TestDriverCreateClose;
   DriverObject->MajorFunction[IRP_MJ_CLOSE] = TestDriverCreateClose;
   DriverObject->MajorFunction[IRP_MJ_READ] = TestDriverRead;
   DriverObject->MajorFunction[IRP_MJ_WRITE] = TestDriverWrite;

   DriverObject->DriverUnload = Unload;

   return STATUS_SUCCESS;
}

void Unload(_In_ PDRIVER_OBJECT DriverObject)
{
   UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK);

   IoDeleteDevice(DriverObject->DeviceObject);
   IoDeleteSymbolicLink(&symLink);
}

NTSTATUS TestDriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
   UNREFERENCED_PARAMETER(DeviceObject);

   Irp->IoStatus.Status = STATUS_SUCCESS;
   Irp->IoStatus.Information = 0;
   IoCompleteRequest(Irp, IO_NO_INCREMENT);
   return STATUS_SUCCESS;
}

NTSTATUS TestDriverRead(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
   unsigned char data = 0;
   char ashex[2];
   PIO_STACK_LOCATION pIOS;
   ULONG buflen;
   PVOID buf;

   pIOS = IoGetCurrentIrpStackLocation(Irp);
   buflen = pIOS->Parameters.Read.Length;
   if(buflen < 2)
   {
      Irp->IoStatus.Status = STATUS_SUCCESS;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
   }
   buf = (PUCHAR)(Irp->AssociatedIrp.SystemBuffer);
   data = __inbyte(0x80);
   byte2hex(&data, 1, ashex, 2);
   RtlCopyMemory(buf, ashex, 2);
   Irp->IoStatus.Status = STATUS_SUCCESS;
   Irp->IoStatus.Information = 2;
   IoCompleteRequest(Irp, IO_NO_INCREMENT);
   return STATUS_SUCCESS;
}

NTSTATUS TestDriverWrite(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
   unsigned char data = 0;
   char ashex[2];
   PIO_STACK_LOCATION pIOS;
   ULONG buflen;
   PVOID buf;

   pIOS = IoGetCurrentIrpStackLocation(Irp);
   buflen = pIOS->Parameters.Write.Length;
   if(buflen < 2)
   {
      Irp->IoStatus.Status = STATUS_SUCCESS;
      Irp->IoStatus.Information = 0;
      IoCompleteRequest(Irp, IO_NO_INCREMENT);
      return STATUS_SUCCESS;
   }
   buf = (PUCHAR)(Irp->AssociatedIrp.SystemBuffer);
   RtlCopyMemory(ashex, buf, 2);
   hex2byte(&data, 1, ashex, 2);
   __outbyte(0x80, data);
   Irp->IoStatus.Status = STATUS_SUCCESS;
   Irp->IoStatus.Information = 2;
   IoCompleteRequest(Irp, IO_NO_INCREMENT);
   return STATUS_SUCCESS;
}

void byte2hex(void *byte, int bytelen, char *hex, int hexlen)
{
   unsigned char b;

   if(hexlen != bytelen * 2) return;
   for(int i = 0, j = 0; i < bytelen; i++, j += 2)
   {
      b = (*(unsigned char*)(byte + i) & 0xf0) >> 4;
      if(b < 10)
      {
         *(hex + j) = '0' + b;
      }
      else
      {
         *(hex + j) = 'W' + b;
      }
      b = *(unsigned char*)(byte + i) & 0x0f;
      if(b < 10)
      {
         *(hex + j + 1) = '0' + b;
      }
      else
      {
         *(hex + j + 1) = 'W' + b;
      }
   }

   return;
}

void hex2byte(void *byte, int bytelen, char *hex, int hexlen)
{
   if(hexlen != bytelen * 2) return;
   for(int i = 0, j = 0; i < hexlen; i++)
   {
      if(!((*(hex + i) >= '0' && *(hex + i) <= '9') || (*(hex + i) >= 'a' && *(hex + i) <= 'f'))) return;
      if(*(hex + i) >= '0' && *(hex + i) <= '9')
      {
         if(!(i % 2))
         {
            *(unsigned char *)(byte + j) = (*(hex + i) - '0') << 4;
         }
         else
         {
            *(unsigned char *)(byte + j) |= *(hex + i) - '0';
            j++;
         }
      }
      else
      {
         if(!(i % 2))
         {
            *(unsigned char *)(byte + j) = (*(hex + i) - 'W') << 4;
         }
         else
         {
            *(unsigned char *)(byte + j) |= *(hex + i) - 'W';
            j++;
         }
      }
   }

   return;
}
```

**Compile the user mode application user.exe from source user.c**

```c
/*
  Windows user-mode application for driver RW minimal example:
  For use with testdrv.sys

  Compile on Linux using mingw:
  /usr/bin/x86_64-w64-mingw32-gcc -o user.exe user.c
*/

#include <windows.h>
#include <stdio.h>
#include <string.h>

int hexchar(char *str);

int main(int argc, char **argv)
{
   HANDLE h;
   char buf[10];
   DWORD dwbt = 0;
   int i;

   if(argc != 2)
   {
      printf("you must supply a one-byte hex value, e.g. 5a\n");
      return -1;
   }
   if(!hexchar(argv[1]))
   {
      printf("you must supply a one-byte hex value, e.g. 5a\n");
      return -1;
   }

   h = CreateFile("\\\\.\\TestDriver", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if(h == INVALID_HANDLE_VALUE)
   {
      printf("error opening file for write.\n");
      return -1;
   }
   if(!WriteFile(h, argv[1], 2, &dwbt, NULL))
   {
      printf("error writing to file.\n");
      return -1;
   }
   CloseHandle(h);
   printf("bytes written %d.\n", dwbt);

   h = CreateFile("\\\\.\\TestDriver", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
   if(h == INVALID_HANDLE_VALUE)
   {
      printf("error opening file for read.\n");
      return -1;
   }
   if(!ReadFile(h, buf, 2, &dwbt, NULL))
   {
      printf("error reading from file.\n");
      return -1;
   }
   CloseHandle(h);
   printf("bytes read %d.\n", dwbt);
   for(i = 0; i < 2; i++)
   {
      printf("%c", buf[i]);
   }
   printf("\n");

   return 0;
}

int hexchar(char *str)
{
   if(strlen(str) != 2) return 0;
   if(!((*str >= '0' && *str <= '9') || (*str >= 'a' && *str <= 'f'))) return 0;
   if(!((*(str + 1) >= '0' && *(str + 1) <= '9') || (*(str + 1) >= 'a' && *(str + 1) <= 'f'))) return 0;
   return 1;
}
```

Copy the driver `testdrv.sys` and user-mode application `user.exe` to a Windows VM.  Windows 10 used in this example with a target path of `e:\misc\`

From a command prompt running as administrator, create the driver service entry using `sc` and start it.

```
sc create "testdrv" binPath= e:\misc\testdrv.sys type= kernel
sc start "testdrv"
```

If you get the following error, restart Windows with signed driver checking disabled (hold down the Shift key while restarting).

![alt text](https://raw.githubusercontent.com/billchaison/windriver/main/01.png)

![alt text](https://raw.githubusercontent.com/billchaison/windriver/main/00.png)

If all goes well you should be able to store a byte in the POST port and read it back out.

![alt text](https://raw.githubusercontent.com/billchaison/windriver/main/02.png)

To remove the driver run the following commands.

```
sc stop "testdrv"
sc delete "testdrv"
```

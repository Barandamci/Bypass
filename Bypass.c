#include <string.h>

// Ban engelleme ile ilgili fonksiyonlar:
//Kraliçem umarım beğenirsiniz (Uncheat Engine 2)
int __fastcall sub_9E574(int *a1)
{
  int result; // r0

  result = prctl(*a1, a1[1], a1[2], a1[3], *(_DWORD *)(a1[46] + a1[13]));
  *a1 = result;
  return result;
}

int __fastcall sub_A6B00(int a1)
{
  _BYTE *v2; // r0
  int v3; // r5
  unsigned __int8 *v4; // r0
  int v5; // r0
  char *v6; // r1
  int v8; // r0
  int v9; // r1
  int *v10; // r0
  int v11; // r0
  int v12; // r1
  int *v13; // r0
  char v14[528]; // [sp+8h] [bp-210h] BYREF

  memset(v14, 0, 0x200u);
  v2 = sub_38C468(v14, 512);
  if ( !v2 )
  {
    *(_BYTE *)(a1 + 32) = 1;
    v5 = 701;
    goto LABEL_5;
  }
  if ( sub_A6C10((int)v2, v14) )
  {
    v3 = sub_CB9E4();
    v4 = sub_38E9D0(214);
    (*(void (__fastcall **)(int, unsigned __int8 *, _DWORD, int))(*(_DWORD *)v3 + 8))(v3, v4, 0, a1 + 4);
    *(_BYTE *)(a1 + 32) = 1;
    v5 = 702;
LABEL_5:
    v6 = 0;
    goto LABEL_6;
  }
  *(_DWORD *)(a1 + 12) = prctl(3, 0, 0, 0, 0);
  v8 = prctl(4, 1, 0, 0, 0);
  if ( v8 )
  {
    v10 = (int *)_errno(v8, v9);
    v6 = strerror(*v10);
    *(_BYTE *)(a1 + 32) = 1;
    v5 = 703;
  }
  else
  {
    v11 = sub_A6CEA(a1);
    if ( !v11 )
      sub_A6D40();
    v13 = (int *)_errno(v11, v12);
    v6 = strerror(*v13);
    *(_BYTE *)(a1 + 32) = 1;
    v5 = 704;
  }
LABEL_6:
  sub_B3D34(v5, v6);
  return -1;
}

int __fastcall sub_AA398(int a1, _DWORD *a2, unsigned int a3)
{
  unsigned int v3; // r3
  int result; // r0
  int v5[4]; // [sp+0h] [bp-10h] BYREF

  v5[0] = (int)a2;
  v5[1] = a3;
  if ( !a2 )
    return -1;
  v3 = a2[1];
  if ( v3 > a3 >> 2 )
    return -1;
  *a2 = a2[v3];
  result = ptrace(PTRACE_GETEVENTMSG|PTRACE_POKETEXT, *(_DWORD *)(a1 + 56), 1, v5);
  if ( result )
    return -1;
  return result;
}

int __fastcall sub_107080(int a1, int a2)
{
  int result; // r0
  int v3; // [sp+4h] [bp-34h]
  int v4; // [sp+8h] [bp-30h] BYREF
  int v5[10]; // [sp+10h] [bp-28h] BYREF

  v5[7] = 2147418112;
  v5[6] = 6;
  v5[5] = 196608;
  v5[3] = a2;
  v5[4] = 6;
  v5[2] = 16777237;
  v5[1] = 0;
  v5[0] = 32;
  if ( prctl(38, 1, 0, 0, 0, v3, 4, v5) )
    return -1;
  result = prctl(22, 2, &v4, 0, 0);
  if ( result )
    return -1;
  return result;
}

int __fastcall sub_107DBE(int a1)
{
  void *v2; // r0

  v2 = *(void **)a1;
  if ( (unsigned int)v2 + 1 >= 2 && !sub_366880(v2, *(void **)(a1 + 4), &byte_7) )
    cacheflush(*(_DWORD *)a1, *(_DWORD *)(a1 + 4) + *(_DWORD *)a1, 0);
  return a1;
}

int __fastcall sub_15E3B4(int a1, void *a2, size_t a3, int a4, int a5)
{
  _DWORD *v5; // r0
  int v6; // r1
  int *v7; // r0
  _DWORD *v8; // r0
  int v9; // r1
  int *v10; // r0
  int v12; // [sp+Ch] [bp-64h]
  char *v13; // [sp+10h] [bp-60h]
  int v14; // [sp+1Ch] [bp-54h]
  char *v15; // [sp+20h] [bp-50h]
  char v17; // [sp+4Bh] [bp-25h]
  _DWORD v18[4]; // [sp+4Ch] [bp-24h] BYREF
  _DWORD v19[4]; // [sp+5Ch] [bp-14h] BYREF

  if ( mprotect(a2, a3, a4) == -1 )
  {
    v5 = sub_1A6B50(v19, 71);
    v7 = (int *)_errno(v5, v6);
    v15 = strerror(*v7);
    sub_1A6D7C((int)v19, v15);
    v14 = sub_1A7B08();
    (*(void (__fastcall **)(int, _DWORD *))(*(_DWORD *)v14 + 8))(v14, v19);
    v17 = 0;
    sub_146838((int)v19);
  }
  else if ( a5 && prctl(1398164801, 0, a2, 4096, a5) < 0 )
  {
    v8 = sub_1A6B50(v18, 47);
    v10 = (int *)_errno(v8, v9);
    v13 = strerror(*v10);
    sub_1A6D7C((int)v18, v13);
    v12 = sub_1A7B08();
    (*(void (__fastcall **)(int, _DWORD *))(*(_DWORD *)v12 + 8))(v12, v18);
    v17 = 0;
    sub_146838((int)v18);
  }
  else
  {
    v17 = 1;
  }
  return v17 & 1;
}

int __fastcall sub_1D97AC(int a1, int a2)
{
  int v3; // [sp+74h] [bp-8Ch]
  void *v4; // [sp+78h] [bp-88h]
  int v8; // [sp+88h] [bp-78h] BYREF
  int v9; // [sp+8Ch] [bp-74h] BYREF
  int v10; // [sp+90h] [bp-70h] BYREF
  struct timezone v11; // [sp+94h] [bp-6Ch] BYREF
  struct timeval v12; // [sp+9Ch] [bp-64h] BYREF
  struct timezone tz; // [sp+A4h] [bp-5Ch] BYREF
  struct timeval tv; // [sp+ACh] [bp-54h] BYREF
  Elf32_Rel *v15; // [sp+B4h] [bp-4Ch] BYREF
  int v16; // [sp+B8h] [bp-48h]
  Elf32_Rel *v17; // [sp+BCh] [bp-44h]
  int v18; // [sp+C0h] [bp-40h] BYREF
  int v19; // [sp+C4h] [bp-3Ch]
  Elf32_Rel *v20; // [sp+C8h] [bp-38h]
  int v21[10]; // [sp+CCh] [bp-34h] BYREF

  v4 = (void *)dword_4A5BD0;
  v10 = 0;
  v9 = 0;
  v18 = *(_DWORD *)"(0";
  v19 = 0;
  v20 = &stru_3038;
  v15 = &stru_3098;
  v16 = 0;
  v17 = &stru_3038;
  if ( (byte_4A5BCC & 1) == 0 || !dword_4A5BD0 || (byte_4A5BCD & 1) != 0 )
    return dword_4A5BA4(a1, a2);
  gettimeofday(&tv, &tz);
  if ( !dword_4A5BE4 )
    dword_4A5B7C(1, &dword_4A5BE4);
  dword_4A5B80(3553, dword_4A5BE4);
  dword_4A5B98(a1, a2, 12375, &dword_4A5BD8);
  dword_4A5B98(a1, a2, 12374, &dword_4A5BDC);
  dword_4A5B84(3553, 0, 6407, 0, 0, dword_4A5BD8, dword_4A5BDC, 0);
  dword_4A5BEC = a1;
  if ( !dword_4A5B98(a1, a2, 12328, &v9) )
    goto LABEL_18;
  v19 = v9;
  if ( !dword_4A5B9C(a1, &v18, v21, 10, &v8) )
    goto LABEL_18;
  if ( v8 > 0 )
    dword_4A5BF0 = v21[0];
  v3 = dword_4A5BA0();
  if ( !dword_4A5BC4(dword_4A5BEC, v3, 12440, &v10) )
    goto LABEL_18;
  v16 = v10;
  if ( !dword_4A5BF4 )//Beyza Karasu
    dword_4A5BF4 = dword_4A5BAC(dword_4A5BEC, dword_4A5BF0, v3, &v15);
  if ( dword_4A5BF4
    && (gettimeofday(&v12, &v11),
        dword_4A5BE0 = sub_3B4A64((v12.tv_sec - tv.tv_sec) * (_DWORD)&loc_F4240 + v12.tv_usec - tv.tv_usec, 1000),
        !sub_1D93C4((void *(*)(void *))sub_1D9E5C, v4, 0)) )
  {
    byte_4A5BCD = 1;
  }
  else
  {
LABEL_18:
    pthread_mutex_unlock((pthread_mutex_t *)&unk_4A5BC8);
    if ( dword_4A5BD0 )
      free((void *)dword_4A5BD0);
    byte_4A5BCC = 0;
  }
  dword_4A5BD0 = 0;
  return dword_4A5BA4(a1, a2);
}

int __fastcall sub_1DCEF8(_DWORD *a1)
{
  const char ***v1; // r0
  void *handle; // [sp+Ch] [bp-14h]

  v1 = (const char ***)sub_151F68(a1 + 9, 0);
  handle = dlopen(**v1, 0);
  if ( handle )
    dlclose(handle);
  *a1 = handle;
  return 1;
}

int __fastcall sub_1E2DD4(_DWORD *a1)
{
  char v1; // r0
  int v2; // r0
  int v3; // r0
  int v5; // [sp+14h] [bp-3Ch]
  const char *v6; // [sp+18h] [bp-38h]
  int v7; // [sp+28h] [bp-28h]
  char v9; // [sp+3Fh] [bp-11h]
  int v10; // [sp+40h] [bp-10h] BYREF
  int v11; // [sp+44h] [bp-Ch] BYREF
  int v12; // [sp+48h] [bp-8h] BYREF

  v1 = byte_4A5C24;
  __dmb(0xBu);
  if ( (v1 & 1) == 0 && sub_3AA830((unsigned __int8 *)&byte_4A5C24) )
  {
    sub_1E3028((int)&unk_4A5C18);
    _cxa_atexit((void (__fastcall *)(void *))sub_1E30A0, &unk_4A5C18, &off_448B0C);
    ((void (__fastcall *)(char *))loc_3AA908)(&byte_4A5C24);
  }
  v12 = **(_DWORD **)sub_151F68(a1 + 9, 0);
  v7 = **(_DWORD **)sub_151F68(a1 + 9, 1);
  v11 = sub_1E30D0((int)&unk_4A5C18, &v12);
  v10 = sub_1E3174();
  if ( sub_1E3148(&v11, &v10) )
  {
    v6 = **(const char ***)sub_151F68(a1 + 9, 2);
    v2 = sub_1E31E4((int)&unk_4A5C18, &v12);
    sub_1661D0(v2, v6);
  }
  v5 = v12;
  sub_1E31E4((int)&unk_4A5C18, &v12);
  sub_147274();
  if ( prctl(1398164801, 0, v5, v7, v3) )
  {
    *a1 = 0;
    v9 = 0;
  }
  else
  {
    *a1 = 1;
    v9 = 1;
  }
  return v9 & 1;
}//t.me/BeyzaSource

int __fastcall sub_223AD8(int a1, struct timeval *a2, struct timezone *a3)
{
  if ( *(_DWORD *)(a1 + 28) )
    return (*(int (__fastcall **)(struct timeval *, struct timezone *))(a1 + 28))(a2, a3);
  else
    return gettimeofday(a2, a3);
}

int __fastcall sub_24C9B0(int a1, int a2, int a3)
{
  int v3; // r0
  int v4; // r0
  _DWORD *v6; // [sp+0h] [bp-28h]
  unsigned int n; // [sp+4h] [bp-24h]
  int v8; // [sp+8h] [bp-20h]
  int v9; // [sp+Ch] [bp-1Ch]
  void *src; // [sp+14h] [bp-14h]

  if ( (*(_BYTE *)(a2 + 271) & 1) != 0 )
  {
    src = (void *)((unsigned int)sub_271214 & 0xFFFFFFFE);
    n = ((unsigned int)nullsub_14 & 0xFFFFFFFE) - ((unsigned int)sub_271214 & 0xFFFFFFFE);
    v3 = sub_1733E4((unsigned int)sub_271214 & 0xFFFFFFFE, n);
  }
  else
  {
    src = (void *)((unsigned int)sub_2711D0 & 0xFFFFFFFE);
    n = ((unsigned int)nullsub_15 & 0xFFFFFFFE) - ((unsigned int)sub_2711D0 & 0xFFFFFFFE);
    v3 = sub_1733E4((unsigned int)sub_2711D0 & 0xFFFFFFFE, n);
  }
  v9 = v3;
  v8 = v3 + 4;
  v4 = sub_24BA44();
  v6 = sub_24BFAC(v4, *(_DWORD *)(a2 + 80), -1);
  if ( !v6 )
    return -1;
  *(_DWORD *)(a2 + 76) = sub_24B628(v6, a2);
  if ( !*(_DWORD *)(a2 + 76) )
    return -1;
  memcpy(*(void **)(a2 + 76), src, n);
  if ( a3 )
    *(_DWORD *)(*(_DWORD *)(a2 + 76) + v9) = a3;
  else
    *(_DWORD *)(*(_DWORD *)(a2 + 76) + v9) = sub_2718E4;
  *(_DWORD *)(*(_DWORD *)(a2 + 76) + v8) = a2;
  cacheflush(*(_DWORD *)(a2 + 76), *(_DWORD *)(a2 + 76) + 384, 0);
  return 0;
}

int __fastcall sub_24CEA0(int a1, int a2)
{
  if ( (*(_BYTE *)(a2 + 233) & 1) != 0 || (*(_BYTE *)(a2 + 271) & 1) != 0 )
  {//MemCpy 1.7 @BeyzaSource
    memcpy((void *)(*(_DWORD *)(a2 + 172) + 4), (const void *)(a2 + 136), *(_DWORD *)(a2 + 132));
  }
  else if ( sub_2714D8(*(_DWORD *)(a2 + 68), a2 + 136, *(_DWORD *)(a2 + 172) + 4, *(_DWORD *)(a2 + 132)) )
  {
    memcpy((void *)(*(_DWORD *)(a2 + 172) + 4), (const void *)(a2 + 136), *(_DWORD *)(a2 + 132));
  }
  cacheflush(*(_DWORD *)(a2 + 172), *(_DWORD *)(a2 + 172) + 128, 0);
  return 0;
}

int __fastcall sub_258B60(struct timeval *a1, struct timezone *a2)
{
  unsigned int result; // r0

  result = linux_eabi_syscall(__NR_gettimeofday, a1, a2);
  if ( result > 0xFFFFF000 )
    return sub_3B5E38(-result);
  return result;
}

int __fastcall sub_26E2D8(int a1)
{
  int (__fastcall *v2)(int (__fastcall *)(int, int, int), int); // [sp+4h] [bp-24h]
  char name[16]; // [sp+Ch] [bp-1Ch] BYREF

  strcpy(name, "dl_iterate_phdr");
  v2 = (int (__fastcall *)(int (__fastcall *)(int, int, int), int))dlsym((void *)0xFFFFFFFF, name);
  return v2(sub_26F3F8, a1);
}

int __fastcall sub_2986D0(int a1, void *a2, void *a3)
{
  unsigned int result; // r0

  result = linux_eabi_syscall(__NR_prctl, a1, a2, a3);
  if ( result > 0xFFFFF000 )
    return sub_3B5E38(-result);
  return result;
}

int __fastcall sub_361D58(_BYTE *a1)
{
  if ( a1 && *a1 )
    return j_prctl(15);
  else
    return -1;
}

int __fastcall sub_361D6C(int a1, int a2)
{
  if ( a1 && a2 )
    return j_prctl(16);
  else
    return -1;
}

int __fastcall sub_361F04(int a1)
{
  *(_BYTE *)a1 = 1;
  return j_gettimeofday((struct timeval *)(a1 + 4), 0);
}

int __fastcall sub_361F38(int a1)
{
  gettimeofday((struct timeval *)(a1 + 12), 0);
  return (*(_DWORD *)(a1 + 16) - *(_DWORD *)(a1 + 8)) / 1000 + 1000 * (*(_DWORD *)(a1 + 12) - *(_DWORD *)(a1 + 4));
}

int __fastcall sub_364066(int a1, int a2)
{
  *(_DWORD *)(a1 + 16) = a2;
  gettimeofday((struct timeval *)a1, 0);
  *(_QWORD *)(a1 + 8) = *(_QWORD *)a1;
  return a1;
}

int __fastcall sub_364080(int a1)
{
  _DWORD *v1; // r5

  v1 = (_DWORD *)(a1 + 8);
  gettimeofday((struct timeval *)(a1 + 8), 0);
  **(_DWORD **)(a1 + 16) = sub_361780((_DWORD *)a1, v1);
  return a1;
}

int __fastcall sub_3648F4(void *a1, void *a2, int a3, void *a4)
{
  if ( (dword_4A9FE4 & 0x10000) != 0 )
    return sub_3B5FF8(37, a1, a2, a4);
  else
    return j_kill((__pid_t)a1, (int)a2);
}

int __fastcall sub_364B70(void *a1, void *a2, void *a3)
{//Telegram @SnyLeaks 
  if ( (dword_4A9FE4 & 0x20000) != 0 )
    return sub_3673F0(26, a1, a2, a3);
  else
    return j_ptrace((enum __ptrace_request)a1);
}

int __fastcall sub_364C18(void *a1, void *a2, void *a3)
{
  if ( (dword_4A9FE4 & 0x200000) != 0 )
    return sub_3673F0(172, a1, a2, a3);
  else
    return j_prctl((int)a1);
}

int __fastcall sub_37D104(int a1, int a2)
{
  return j_cacheflush(a1, a2 + a1, 0);
}

int __fastcall sub_3865A2(int a1)
{
  int result; // r0

  do
  {//Telegram @ElifOwner @SuneyyePubg
    gettimeofday((struct timeval *)(a1 + 140), 0);
    gettimeofday((struct timeval *)(a1 + 148), 0);
    result = *(_DWORD *)(a1 + 168);
    *(_QWORD *)(a1 + 148) = 0LL;
    *(_QWORD *)(a1 + 156) = 0LL;
    *(_DWORD *)(a1 + 128) = 0;
    *(_DWORD *)(a1 + 132) = 0;
    *(_DWORD *)(a1 + 136) = 0;
    *(_BYTE *)(a1 + 64) = 0;
    *(_BYTE *)a1 = 0;
    *(_BYTE *)(a1 + 164) = 0;
    a1 = result;
  }
  while ( result );
  return result;
}
//(Uncheat Engine 2-4 MemCpy v1.7 engine)
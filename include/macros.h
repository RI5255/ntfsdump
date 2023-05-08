#ifndef __MACROS_H__
#define __MACROS_H__

#define MERGE(a,b)  a##b
#define LABEL1(a) MERGE(_unknown, a)
#define LABEL2(a) MERGE(_unused, a)
#define Unknown LABEL1(__LINE__)
#define Unused  LABEL2(__LINE__)

#endif
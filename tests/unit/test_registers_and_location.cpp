#include <gtest/gtest.h>
#include "registers.h"
#include "symbolObject.h"
#include "dwarf.h"

TEST(RegistersTest, DefaultInitializationToZero)
{
	Registers regs;
	EXPECT_EQ(regs.rax, 0u);
	EXPECT_EQ(regs.rbx, 0u);
	EXPECT_EQ(regs.rcx, 0u);
	EXPECT_EQ(regs.rdx, 0u);
	EXPECT_EQ(regs.rsi, 0u);
	EXPECT_EQ(regs.rdi, 0u);
	EXPECT_EQ(regs.rbp, 0u);
	EXPECT_EQ(regs.rsp, 0u);
	EXPECT_EQ(regs.r8, 0u);
	EXPECT_EQ(regs.r9, 0u);
	EXPECT_EQ(regs.r10, 0u);
	EXPECT_EQ(regs.r11, 0u);
	EXPECT_EQ(regs.r12, 0u);
	EXPECT_EQ(regs.r13, 0u);
	EXPECT_EQ(regs.r14, 0u);
	EXPECT_EQ(regs.r15, 0u);
	EXPECT_EQ(regs.rip, 0u);
	EXPECT_EQ(regs.rflags, 0u);
}

TEST(RegistersTest, RegisterAssignmentAndValues)
{
	Registers regs;
	regs.rax = 0x1122334455667788ULL;
	regs.rsp = 0x7fffffffe000ULL;
	regs.rip = 0x555555554000ULL;

	EXPECT_EQ(regs.rax, 0x1122334455667788ULL);
	EXPECT_EQ(regs.rsp, 0x7fffffffe000ULL);
	EXPECT_EQ(regs.rip, 0x555555554000ULL);
}

TEST(LocationTest, RangeCheck)
{
	Dwarf_Locdesc_c dummyDesc = nullptr;
	Location loc(0x1000, 0x2000, dummyDesc, 0);

	EXPECT_FALSE(loc.inRange(0x0FFF));
	EXPECT_TRUE(loc.inRange(0x1000));
	EXPECT_TRUE(loc.inRange(0x1500));
	EXPECT_TRUE(loc.inRange(0x2000));
	EXPECT_FALSE(loc.inRange(0x2001));
}

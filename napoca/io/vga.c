/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file vga.c
*   @brief VGA - legacy VGA 80x25 text mode support
*
*/

#include "napoca.h"

static WORD *gVgaMem = (WORD*)(VOID*)0x00000000000B8000ULL; ///< Legacy VGA start address, use identity mapping for legacy VGA
static WORD gVgaCursor = 0;                                 ///< Vga cursor, starts at the first line

#define VGA_CLEAR       ((WORD)0x0720)       ///< Used to "clear" screen
#define VGA_WIDTH       80                   ///< Width of the Legacy Text mode screen

static WORD gVgaColor = VGA_CLEAR & 0xFF00;         ///< The used color for printing to the VGA screen
static WORD gVgaHeight = 50;                        ///< Height of the Legacy Text mode screen (can be 25 or extended 50)

//
// Christmas tree, use in time of the Christmas holidays :)
//
#define TREE_WIDTH  13               ///< Width of the Christmas tree
#define TREE_HEIGHT 7                ///< Height of the Christmas tree

#define B   2       ///< black background
#define T   1       ///< tree "pixel"
#define F   0       ///< snow flakes
#define O   5       ///< ornament
#define L   0xF     ///< led

/// @brief Christmas tree pattern
static BYTE gPattern[TREE_WIDTH*TREE_HEIGHT] = {
    B, F, B, F, B, F, O, F, B, F, B, F, B,
    F, B, F, B, F, L, T, L, F, B, F, B, F,
    B, F, B, F, O, T, L, T, O, F, B, F, B,
    F, B, F, L, T, O, T, O, T, L, F, B, F,
    B, F, O, T, L, T, O, T, L, T, O, F, B,
    F, L, T, O, T, T, L, T, T, O, T, L, F,
    B, F, B, F, B, F, F, F, B, F, B, F, B
};


//
// BGGGFFFF CCCCCCCC--> VGA format: B - blinking, G - background color bit, F - foreground color bits (attributes also), C - character displayed
//


///
/// @brief        Static function which moves/sets the cursor on the screen to the value contained in #gVgaCursor. It does by writing to the
///               specific legacy ports (0x03D4, 0x03D5).
///
static void
VgaSetCRTCCursor(
    void
    )
{
    WORD cursor;

    cursor = gVgaCursor;

    __outbyte(0x03D4, 0x0E);
    __outbyte(0x03D5, (cursor & 0xFF00) >> 8);
    __outbyte(0x03D4, 0x0F);
    __outbyte(0x03D5, cursor & 0x00FF);
}


///
/// @brief        Static function which gets/reads the cursor on the screen and stores the value to #gVgaCursor. It does by writing to port 0x03D4
///               and reading back from port 0x03D5.
///
static void
VgaGetCRTCCursor(
    void
    )
{
    WORD cursor;

    __outbyte(0x03D4, 0x0E);
    cursor = ((WORD)__inbyte(0x03D5)) << 8;
    __outbyte(0x03D4, 0x0F);
    cursor |= __inbyte(0x03D5);

    gVgaCursor = cursor;
}


///
/// @brief        It shifts up every line (scrolls up) the text (the first line is deleted) and clears the last line of the VGA display.
///
/// @remark       The Banner remains intact
///
static void
VgaScrollUp(
    void
    )
{
    int i;

    for (i=VGA_WIDTH; i<VGA_WIDTH*(gVgaHeight-1); i++)
        *(gVgaMem + i) = *(gVgaMem + i + VGA_WIDTH);

    for (i=0; i<VGA_WIDTH; i++)
        *(gVgaMem + VGA_WIDTH*(gVgaHeight-1ull) + i) = VGA_CLEAR;
}

NTSTATUS
VgaInit(
    _In_ BYTE ScreenHeight
)
{
    VgaGetCRTCCursor();
    gVgaHeight = ScreenHeight;

    return CX_STATUS_SUCCESS;
}

NTSTATUS
VgaClear(
    void
    )
{
    int i;

    for (i=0; i < VGA_WIDTH*(gVgaHeight) - 1; i++)
        *(gVgaMem + i) = VGA_CLEAR;

    gVgaCursor = 0;
    VgaSetCRTCCursor();

    return CX_STATUS_SUCCESS;
}

NTSTATUS
VgaSetCursorPos(
    _In_ BYTE Line,
    _In_ BYTE Column
    )
{
    gVgaCursor = (WORD)((Line-1) * VGA_WIDTH + (Column-1));
    VgaSetCRTCCursor();
    return CX_STATUS_SUCCESS;
}

NTSTATUS
VgaWrite(
    _In_ CHAR *Buffer,
    _In_ WORD Length
    )
{
    while (Length > 0)
    {
        switch (*Buffer)
        {
        case '\n':
            if (gVgaColor != (VGA_CLEAR & 0xff00))
            {
                // Fill the rest of the line
                int i;
                for (i = gVgaCursor; i < gVgaCursor + (VGA_WIDTH - gVgaCursor % VGA_WIDTH); i++)
                {
                    *(gVgaMem + i) = ' ' | gVgaColor;
                }
            }
            gVgaCursor = ((gVgaCursor + VGA_WIDTH) / VGA_WIDTH) * VGA_WIDTH;
            if (gVgaCursor >= VGA_WIDTH*gVgaHeight)
            {
                VgaScrollUp();
                gVgaCursor -= VGA_WIDTH;
            }
            break;
        default:
            *(gVgaMem + gVgaCursor) = (*Buffer) | gVgaColor;
            if (++gVgaCursor >= VGA_WIDTH*gVgaHeight)
            {
                VgaScrollUp();
                gVgaCursor -= VGA_WIDTH;
            }
            break;
        }

        Buffer++;
        Length--;
    }

    VgaSetCRTCCursor();
    return CX_STATUS_SUCCESS;
}

WORD
VgaSetColor(
    _In_ WORD Color
    )
{
    WORD x = gVgaColor;
    gVgaColor = Color;
    return x;
}

VOID
VgaSetLoadProgress(
    _In_ BYTE Percentage
    )
{
    WORD vgaCursor;
    BYTE completed;
    DWORD i;

    if (Percentage > 100) Percentage = 100;

    completed = Percentage /5;     // completed characters

    vgaCursor = VGA_WIDTH - 20;

    for (i = 0; i < 20; i++)
    {
        WORD pos;
        if (i < completed) pos = 0x2F00;
        else pos = 0x6F00;

        if ((Percentage == 100 ) && (i == 15))
        {
            pos = pos | '1';
            *(gVgaMem + vgaCursor + i) = pos;
        }

        if (i == 10)
        {
            if (Percentage < 35)               // 35 we are at the end of phase1
            {
                pos = pos | '1';
                *(gVgaMem + vgaCursor + i) = pos;
            }
            else if (Percentage < 75)          // 75 we are at the end of phase2
            {
                pos = pos | '2';
                *(gVgaMem + vgaCursor + i) = pos;
            }
            else
            {
                pos = pos | '3';
                *(gVgaMem + vgaCursor + i) = pos;
            }
        }

        if ((Percentage >= 10) && (i == 16))
        {
            pos = pos | ('0' + (Percentage / 10) % 10);
            *(gVgaMem + vgaCursor + i) = pos;
        }
        else if (i == 17)
        {
            pos = pos | ('0' + (Percentage % 10));
            *(gVgaMem + vgaCursor + i) = pos;
        }
        else *(gVgaMem + vgaCursor + i) = (*(gVgaMem + vgaCursor + i) & 0xFF) | pos;
    }
}

VOID
VgaSetBanner(
    _In_ CHAR *String1,
    _In_ CHAR *String2
    )
{
    WORD vgaColor;
    WORD cursor = 0;

    gVgaCursor = 0;

    vgaColor = VgaSetColor(0x1e00);
    VgaWrite(String1, (WORD)strlen(String1));

    VgaSetColor(0x7400);
    VgaWrite(String2, (WORD)strlen(String2));

    gVgaCursor = VGA_WIDTH - 20;
    VgaSetColor(0x6F00);
    VgaWrite(" Loading S0...   0% ", 20);

    VgaSetColor(0x7400);
    for (cursor = gVgaCursor; cursor <= VGA_WIDTH; cursor++)
    {
        VgaWrite(" ", 1);
    }

    VgaSetColor(vgaColor);
    gVgaCursor = 81;
}

VOID
VgaChristmas(
    void
    )
{
    DWORD i,j;
    WORD start = VGA_WIDTH * 2 - TREE_WIDTH;
    WORD vgaCursor = gVgaCursor;

    gVgaCursor = start;

    for (i = 0; i < TREE_HEIGHT; i++)
    {
        for (j = 0; j < TREE_WIDTH; j++)
        {
            BYTE x = gPattern[i*TREE_WIDTH + j];
            WORD c = 0;

            if (x & 1) c |= 0x2000;        // green BG

            if (x & 8) c |= 0x8000;        // blink

            switch ((x >> 1) & 3)
            {
            case 0:
                c |= ' ';
                break;
            case 1:
                c |= '*';
                c |= 0x0b00;        // cyan
                break;
            case 2:
                c |= 'o';
                c |= 0x0c00;        // red
                break;
            case 3:
                c |= 'x';
                c |= 0x0e00;        // yellow
                break;
            }

            gVgaMem[gVgaCursor] = c;

            gVgaCursor++;
        }
        gVgaCursor += VGA_WIDTH - TREE_WIDTH;
    }

    gVgaCursor = gVgaCursor + 6 - VGA_WIDTH;
    gVgaMem[gVgaCursor] = 0x4020;
    gVgaCursor = vgaCursor;
    VgaSetCRTCCursor();
}

VOID
VgaHalt(
    void
    )
{
    WORD vgaCursor = gVgaCursor;
    WORD vgaColor;

    gVgaCursor = VGA_WIDTH - 6;

    vgaColor = VgaSetColor(0xcf00);
    VgaWrite(" HALT ", 6);

    VgaChristmas();

    VgaSetColor(vgaColor);
    gVgaCursor = vgaCursor;
    VgaSetCRTCCursor();
}

VOID
VgaDebug(
    void
    )
{
    WORD vgaCursor = gVgaCursor;
    WORD vgaColor;

    if (!gVideoVgaInited) return;

    gVgaCursor = VGA_WIDTH - 17;

    vgaColor = VgaSetColor(0xbe00);
    VgaWrite(" DEBUG ", 7);

    VgaSetColor(0x0e00);
    gVgaCursor = vgaCursor;
    VgaSetCRTCCursor();
}

VOID
VgaBugcheck(
    void
    )
{
    WORD vgaCursor = gVgaCursor;
    WORD vgaColor;

    if (!gVideoVgaInited) return;

    gVgaCursor = VGA_WIDTH - 10;

    vgaColor = VgaSetColor(0x4f00);
    VgaWrite(" BUGCHECK ", 10);

    VgaSetColor(vgaColor);
    gVgaCursor = vgaCursor;
    VgaSetCRTCCursor();
}

///@}
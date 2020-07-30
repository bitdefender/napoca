/*
* Copyright (c) 2020 Bitdefender
* SPDX-License-Identifier: Apache-2.0
*/

/// @addtogroup io
///@{

/** @file vga.h
*   @brief VGA - legacy VGA 80x25 text mode support
*
*/

#ifndef _VGA_H_
#define _VGA_H_

#include "core.h"



///
/// @brief        Initializes VGA by getting the cursor to the first line and establishing height
///
/// @param[in]    ScreenHeight                     The height in lines of the the screen
///
/// CX_STATUS_SUCCESS                              - always
///
NTSTATUS
VgaInit(
    _In_ BYTE ScreenHeight
);



///
/// @brief        Clears the screen of the VGA back to black and sets the cursor back to the start of the first line.
///
/// CX_STATUS_SUCCESS                              - always
///
NTSTATUS
VgaClear(
    void
);



///
/// @brief        Moves the VGA cursor to the specified Line and Column.
///
/// @param[in]    Line                             The line number from the top of the screen where the cursor should be moved
/// @param[in]    Column                           The Column/character number from the left part of the screen where the cursor should be moved
///
/// CX_STATUS_SUCCESS                              - always
///
NTSTATUS
VgaSetCursorPos(
    _In_ BYTE Line,
    _In_ BYTE Column
);



///
/// @brief        Writes to the VGA screen the content of the text buffer Buffer
///
/// @param[in]    Buffer                           The buffer containing the text to be written
/// @param[in]    Length                           The length of Buffer in bytes
///
/// CX_STATUS_SUCCESS                              - always
///
NTSTATUS
VgaWrite(
    _In_ CHAR *Buffer,
    _In_ WORD Length
);



///
/// @brief        It sets the color of the text which is used at VgaWrite.
///
/// @param[in]    Color                            The new color of the text, 2 bytes having the format: BGGGFFFF B - blinking, G - background color bit, F - foreground color bits (attributes also)
///
/// @returns      WORD                             - returns the old color value, which was overwritten
///
WORD
VgaSetColor(
    _In_ WORD Color
);



///
/// @brief        Writes the content of the banner of the VGA window, representing generic information in the first line which is not overwritten.
///
/// @param[in]    String1                          The first string to be displayed on the banner, the current Napoca version usually
/// @param[in]    String2                          The second string to be displayed on the banner, the company name usually
///
VOID
VgaSetBanner(
    _In_ CHAR *String1,
    _In_ CHAR *String2
);



///
/// @brief        Sets the progress of loading the Hypervisor in percentage. Must be called after every major step/phase/component load.
///               The percentage is displayed as a load bar inside the banner.
///
/// @param[in]    Percentage                       The current percentage of the loading/booting progress from [0..100]
///
VOID
VgaSetLoadProgress(
    _In_ BYTE Percentage
);



///
/// @brief        It displays the message halt on the screen and draws a Christmas tree. Use only during Christmas holidays!
///
VOID
VgaHalt(
    void
);



///
/// @brief        It displays the message BUGCHECK after which one might print the related information to the Hypervisors failure. Only debug purposes.
///
VOID
VgaBugcheck(
    void
    )
;



///
/// @brief        It displays the message DEBUG after which one might try to enter the debugger or halt the HV. Only debug purposes
///
VOID
VgaDebug(
    void
    )
;



///
/// @brief        Function used to draw a Christmas tree onto the VGA screen, use only during Christmas holidays!
///
VOID
VgaChristmas(
    void
    )
;

#endif // _VGA_H_

///@}
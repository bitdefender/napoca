%define MULTIBOOT_NAMES_COUNT 7
strCommandLine:  db "commandLine", 0
strExceptions:   db "exceptions", 0
strGuestLoader:  db "guestLoader", 0
strIntro:        db "intro", 0
strKernel:       db "kernel", 0
strLiveintroupd: db "liveintroupd", 0
strSettings:     db "settings", 0
MultibootModuleNameToModId:
    dd RVA(strCommandLine),                   LD_MODID_COMMAND_LINE
    dd RVA(strExceptions),                    LD_MODID_INTRO_EXCEPTIONS
    dd RVA(strGuestLoader),                   LD_MODID_ORIG_MBR
    dd RVA(strIntro),                         LD_MODID_INTRO_CORE
    dd RVA(strKernel),                        LD_MODID_NAPOCA_IMAGE
    dd RVA(strLiveintroupd),                  LD_MODID_INTRO_LIVE_UPDATE
    dd RVA(strSettings),                      LD_MODID_MBR_SETTINGS
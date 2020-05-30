# keyboard-tester, for linux & macOS

Written so I could test macbook keyboards before sending back to clients after a board repair or similar service.

Works on keyboard scancodes, not keycodes, so will work with all keyboards but you'll be left with varying levels of keys that aren't "pressed".

#### BETA DEVELOPMENT --- Seems to be okay to use now

### Prerequisites

Requires SDL2 and SDL2_ttf

linux
```
apt install libsdl2-dev
```

macOS
```
brew install libsdl2 libsd2_ttf
```

### Build
```make```

### Parameters
```
keyboard-tester [--dl <lower bound ms>] [--dh <upper bound ms>] [-m <mapfile>] [-c] [--dpi <dpi>] [--fs <pts>] [-d]

--dl <time (20 ms default)> : Set acceptable lower limit of key down time
--dh <time (200 ms default)> : Set acceptable upper limit of key down time
-m <mapfile> : Set keyboard map to use, limits keys and sets names to test
-c : Close tester when all keys have been pressed

--kwidth <px> : Width of key in pixels
--kheight <px> : Height of key in pixels
--kspacing <px> : Gap between keys in pixels
--columns <n> : How many columns of keys to show
--compact : Remove null/empty keys from grid display

--colbg <rrggbb> : background
--colkey <rrggbb> : key block
--coltext <rrggbb> : key text
--colpressed <rrggbb> : key block colour while pressed
--colreport <rrggbb> : after-pressed report text (normal)
--colflagged <rrggbb> : after-pressed report text (flagged)

--dpi <dpi> : Force screen DPI
--fs <pts> : Set font size in pts
--fscale : Scale the key text rather than cropping

-d : Enable debugging output

        ALT/OPT-Q: exit/quit
        ALT/OPT-M: Save current pressed keyset to mapfile
```

### Application Controls
```
	alt-q / opt-q : quit
	alt-m / opt-m : Save currently pressed keys array to map file
```

### Screenshots
![Screenshot](assets/images/ss-1.jpg)

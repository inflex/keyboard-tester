#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <stdio.h>

#define KEYMAP_SIZE 285 // how many actual keyboard scancodes there are that SDL2 recognises

#define KEY_WIDTH 70
#define KEY_HEIGHT 20
#define KEY_SPACING 3
#define KEYS_ACROSS 16
#define KEYS_DOWN 20
#define KEY_PADDING 2
#define SCREEN_WIDTH (KEY_WIDTH +KEY_SPACING) *KEYS_ACROSS +KEY_SPACING
#define SCREEN_HEIGHT (KEY_HEIGHT +KEY_SPACING) *KEYS_DOWN +KEY_SPACING

#define FL __FILE__,__LINE__

#define EMPTY_STR ""
#define FONT_NAME "font.ttf"


struct key {
	char *name;
	int pressed;
	int group;
	int x, y;
};


struct globals {
	struct key keys[KEYMAP_SIZE];

	SDL_Window *window;
   SDL_Renderer *renderer;
	SDL_Surface *screenSurface;
	TTF_Font *font;
};



int init( struct globals *g ) {

	int i;

	g->window = NULL;
	g->renderer = NULL;
	g->screenSurface = NULL;

   TTF_Init();
   g->font = TTF_OpenFont(FONT_NAME, 10 );
    if (g->font == NULL) {
        fprintf(stderr, "error: font not found\n");
        exit(EXIT_FAILURE);
    }

	// Initialise the scancode array with
	// all flagged as untouched
	//
	//
	for (i = 0; i < KEYMAP_SIZE; i++) {
		g->keys[i].pressed = 0;
		g->keys[i].name = EMPTY_STR;
		g->keys[i].group = 0;
		g->keys[i].x = 0;
		g->keys[i].y = 0;
	}


	g->keys[0].name = "UNKNOWN";
	g->keys[4].name = "A";
	g->keys[5].name = "B";
	g->keys[6].name = "C";

	g->keys[7].name = "D";
	g->keys[8].name = "E";
	g->keys[9].name = "F";
	g->keys[10].name = "G";

	g->keys[11].name = "H";
	g->keys[12].name = "I";
	g->keys[13].name = "J";
	g->keys[14].name = "K";

	g->keys[15].name = "L";
	g->keys[16].name = "M";
	g->keys[17].name = "N";
	g->keys[18].name = "O";

	g->keys[19].name = "P";
	g->keys[20].name = "Q";
	g->keys[21].name = "R";
	g->keys[22].name = "S";

	g->keys[23].name = "T";
	g->keys[24].name = "U";
	g->keys[25].name = "V";
	g->keys[26].name = "W";

	g->keys[27].name = "X";
	g->keys[28].name = "Y";
	g->keys[29].name = "Z";
	g->keys[30].name = "1";

	g->keys[31].name = "2";
	g->keys[32].name = "3";
	g->keys[33].name = "4";
	g->keys[34].name = "5";

	g->keys[35].name = "6";
	g->keys[36].name = "7";
	g->keys[37].name = "8";
	g->keys[38].name = "9";

	g->keys[39].name = "0";
	g->keys[40].name = "RETURN";
	g->keys[41].name = "ESCAPE";
	g->keys[42].name = "BACKSPACE";

	g->keys[43].name = "TAB";
	g->keys[44].name = "SPACE";
	g->keys[45].name = "MINUS";
	g->keys[46].name = "EQUALS";

	g->keys[47].name = "LEFTBRACKET";
	g->keys[48].name = "RIGHTBRACKET";
	g->keys[49].name = "BACKSLASH";
	g->keys[50].name = "NONUSHASH";

	g->keys[51].name = "SEMICOLON";
	g->keys[52].name = "APOSTROPHE";
	g->keys[53].name = "GRAVE";
	g->keys[54].name = "COMMA";

	g->keys[55].name = "PERIOD";
	g->keys[56].name = "SLASH";
	g->keys[57].name = "CAPSLOCK";
	g->keys[58].name = "F1";

	g->keys[59].name = "F2";
	g->keys[60].name = "F3";
	g->keys[61].name = "F4";
	g->keys[62].name = "F5";

	g->keys[63].name = "F6";
	g->keys[64].name = "F7";
	g->keys[65].name = "F8";
	g->keys[66].name = "F9";

	g->keys[67].name = "F10";
	g->keys[68].name = "F11";
	g->keys[69].name = "F12";
	g->keys[70].name = "PRINTSCREEN";

	g->keys[71].name = "SCROLLLOCK";
	g->keys[72].name = "PAUSE";
	g->keys[73].name = "INSERT";
	g->keys[74].name = "HOME";

	g->keys[75].name = "PAGEUP";
	g->keys[76].name = "DELETE";
	g->keys[77].name = "END";
	g->keys[78].name = "PAGEDOWN";

	g->keys[79].name = "RIGHT";
	g->keys[80].name = "LEFT";
	g->keys[81].name = "DOWN";
	g->keys[82].name = "UP";

	g->keys[83].name = "NUMLOCKCLEAR";
	g->keys[84].name = "KP_DIVIDE";
	g->keys[85].name = "KP_MULTIPLY";
	g->keys[86].name = "KP_MINUS";

	g->keys[87].name = "KP_PLUS";
	g->keys[88].name = "KP_ENTER";
	g->keys[89].name = "KP_1";
	g->keys[90].name = "KP_2";

	g->keys[91].name = "KP_3";
	g->keys[92].name = "KP_4";
	g->keys[93].name = "KP_5";
	g->keys[94].name = "KP_6";

	g->keys[95].name = "KP_7";
	g->keys[96].name = "KP_8";
	g->keys[97].name = "KP_9";
	g->keys[98].name = "KP_0";

	g->keys[99].name = "KP_PERIOD";
	g->keys[100].name = "NONUSBACKSLASH";
	g->keys[101].name = "APPLICATION";
	g->keys[102].name = "POWER";

	g->keys[103].name = "KP_EQUALS";
	g->keys[104].name = "F13";
	g->keys[105].name = "F14";
	g->keys[106].name = "F15";

	g->keys[107].name = "F16";
	g->keys[108].name = "F17";
	g->keys[109].name = "F18";
	g->keys[110].name = "F19";

	g->keys[111].name = "F20";
	g->keys[112].name = "F21";
	g->keys[113].name = "F22";
	g->keys[114].name = "F23";

	g->keys[115].name = "F24";
	g->keys[116].name = "EXECUTE";
	g->keys[117].name = "HELP";
	g->keys[118].name = "MENU";

	g->keys[119].name = "SELECT";
	g->keys[120].name = "STOP";
	g->keys[121].name = "AGAIN";
	g->keys[122].name = "UNDO";

	g->keys[123].name = "CUT";
	g->keys[124].name = "COPY";
	g->keys[125].name = "PASTE";
	g->keys[126].name = "FIND";

	g->keys[127].name = "MUTE";
	g->keys[128].name = "VOLUMEUP";
	g->keys[129].name = "VOLUMEDOWN";
	g->keys[133].name = "KP_COMMA";

	g->keys[134].name = "KP_EQUALSAS400";
	g->keys[135].name = "INTERNATIONAL1";
	g->keys[136].name = "INTERNATIONAL2";
	g->keys[137].name = "INTERNATIONAL3";

	g->keys[138].name = "INTERNATIONAL4";
	g->keys[139].name = "INTERNATIONAL5";
	g->keys[140].name = "INTERNATIONAL6";
	g->keys[141].name = "INTERNATIONAL7";

	g->keys[142].name = "INTERNATIONAL8";
	g->keys[143].name = "INTERNATIONAL9";
	g->keys[144].name = "LANG1";
	g->keys[145].name = "LANG2";

	g->keys[146].name = "LANG3";
	g->keys[147].name = "LANG4";
	g->keys[148].name = "LANG5";
	g->keys[149].name = "LANG6";

	g->keys[150].name = "LANG7";
	g->keys[151].name = "LANG8";
	g->keys[152].name = "LANG9";
	g->keys[153].name = "ALTERASE";

	g->keys[154].name = "SYSREQ";
	g->keys[155].name = "CANCEL";
	g->keys[156].name = "CLEAR";
	g->keys[157].name = "PRIOR";

	g->keys[158].name = "RETURN2";
	g->keys[159].name = "SEPARATOR";
	g->keys[160].name = "OUT";
	g->keys[161].name = "OPER";

	g->keys[162].name = "CLEARAGAIN";
	g->keys[163].name = "CRSEL";
	g->keys[164].name = "EXSEL";
	g->keys[176].name = "KP_00";

	g->keys[177].name = "KP_000";
	g->keys[178].name = "THOUSANDSSEPARATOR";
	g->keys[179].name = "DECIMALSEPARATOR";
	g->keys[180].name = "CURRENCYUNIT";

	g->keys[181].name = "CURRENCYSUBUNIT";
	g->keys[182].name = "KP_LEFTPAREN";
	g->keys[183].name = "KP_RIGHTPAREN";
	g->keys[184].name = "KP_LEFTBRACE";

	g->keys[185].name = "KP_RIGHTBRACE";
	g->keys[186].name = "KP_TAB";
	g->keys[187].name = "KP_BACKSPACE";
	g->keys[188].name = "KP_A";

	g->keys[189].name = "KP_B";
	g->keys[190].name = "KP_C";
	g->keys[191].name = "KP_D";
	g->keys[192].name = "KP_E";

	g->keys[193].name = "KP_F";
	g->keys[194].name = "KP_XOR";
	g->keys[195].name = "KP_POWER";
	g->keys[196].name = "KP_PERCENT";

	g->keys[197].name = "KP_LESS";
	g->keys[198].name = "KP_GREATER";
	g->keys[199].name = "KP_AMPERSAND";
	g->keys[200].name = "KP_DBLAMPERSAND";

	g->keys[201].name = "KP_VERTICALBAR";
	g->keys[202].name = "KP_DBLVERTICALBAR";
	g->keys[203].name = "KP_COLON";
	g->keys[204].name = "KP_HASH";

	g->keys[205].name = "KP_SPACE";
	g->keys[206].name = "KP_AT";
	g->keys[207].name = "KP_EXCLAM";
	g->keys[208].name = "KP_MEMSTORE";

	g->keys[209].name = "KP_MEMRECALL";
	g->keys[210].name = "KP_MEMCLEAR";
	g->keys[211].name = "KP_MEMADD";
	g->keys[212].name = "KP_MEMSUBTRACT";

	g->keys[213].name = "KP_MEMMULTIPLY";
	g->keys[214].name = "KP_MEMDIVIDE";
	g->keys[215].name = "KP_PLUSMINUS";
	g->keys[216].name = "KP_CLEAR";

	g->keys[217].name = "KP_CLEARENTRY";
	g->keys[218].name = "KP_BINARY";
	g->keys[219].name = "KP_OCTAL";
	g->keys[220].name = "KP_DECIMAL";

	g->keys[221].name = "KP_HEXADECIMAL";
	g->keys[224].name = "LCTRL";
	g->keys[225].name = "LSHIFT";
	g->keys[226].name = "LALT";

	g->keys[227].name = "LGUI";
	g->keys[228].name = "RCTRL";
	g->keys[229].name = "RSHIFT";
	g->keys[230].name = "RALT";

	g->keys[231].name = "RGUI";
	g->keys[257].name = "MODE";
	g->keys[258].name = "AUDIONEXT";
	g->keys[259].name = "AUDIOPREV";

	g->keys[260].name = "AUDIOSTOP";
	g->keys[261].name = "AUDIOPLAY";
	g->keys[262].name = "AUDIOMUTE";
	g->keys[263].name = "MEDIASELECT";

	g->keys[264].name = "WWW";
	g->keys[265].name = "MAIL";
	g->keys[266].name = "CALCULATOR";
	g->keys[267].name = "COMPUTER";

	g->keys[268].name = "AC_SEARCH";
	g->keys[269].name = "AC_HOME";
	g->keys[270].name = "AC_BACK";
	g->keys[271].name = "AC_FORWARD";

	g->keys[272].name = "AC_STOP";
	g->keys[273].name = "AC_REFRESH";
	g->keys[274].name = "AC_BOOKMARKS";
	g->keys[275].name = "BRIGHTNESSDOWN";

	g->keys[276].name = "BRIGHTNESSUP";
	g->keys[277].name = "DISPLAYSWITCH";
	g->keys[278].name = "KBDILLUMTOGGLE";
	g->keys[279].name = "KBDILLUMDOWN";
	g->keys[280].name = "KBDILLUMUP";
	g->keys[281].name = "EJECT";
	g->keys[282].name = "SLEEP";
	g->keys[283].name = "APP1";
	g->keys[284].name = "APP2";

	g->keys[0].group = 1;
g->keys[1].group = 1;
g->keys[2].group = 1;
g->keys[3].group = 1;
g->keys[50].group = 1;
g->keys[100].group = 1;
g->keys[101].group = 1;
g->keys[102].group = 1;
g->keys[103].group = 1;
g->keys[104].group = 1;
g->keys[105].group = 1;
g->keys[106].group = 1;
g->keys[107].group = 1;
g->keys[108].group = 1;
g->keys[109].group = 1;
g->keys[110].group = 1;
g->keys[111].group = 1;
g->keys[112].group = 1;
g->keys[113].group = 1;
g->keys[114].group = 1;
g->keys[115].group = 1;
g->keys[116].group = 1;
g->keys[117].group = 1;
g->keys[118].group = 1;
g->keys[119].group = 1;
g->keys[120].group = 1;

g->keys[121].group = 1;
g->keys[122].group = 1;
g->keys[123].group = 1;
g->keys[124].group = 1;
g->keys[125].group = 1;
g->keys[126].group = 1;
g->keys[130].group = 1;

g->keys[131].group = 1;
g->keys[132].group = 1;
g->keys[133].group = 1;
g->keys[134].group = 1;
g->keys[135].group = 1;
g->keys[136].group = 1;
g->keys[137].group = 1;
g->keys[138].group = 1;
g->keys[139].group = 1;
g->keys[140].group = 1;

g->keys[141].group = 1;
g->keys[142].group = 1;
g->keys[143].group = 1;
g->keys[144].group = 1;
g->keys[145].group = 1;
g->keys[146].group = 1;
g->keys[147].group = 1;
g->keys[148].group = 1;
g->keys[149].group = 1;
g->keys[150].group = 1;

g->keys[151].group = 1;
g->keys[152].group = 1;
g->keys[153].group = 1;
g->keys[154].group = 1;
g->keys[155].group = 1;
g->keys[156].group = 1;
g->keys[157].group = 1;
g->keys[158].group = 1;
g->keys[159].group = 1;
g->keys[160].group = 1;

g->keys[161].group = 1;
g->keys[162].group = 1;
g->keys[163].group = 1;
g->keys[164].group = 1;
g->keys[165].group = 1;
g->keys[166].group = 1;
g->keys[167].group = 1;
g->keys[168].group = 1;
g->keys[169].group = 1;
g->keys[170].group = 1;

g->keys[171].group = 1;
g->keys[172].group = 1;
g->keys[173].group = 1;
g->keys[174].group = 1;
g->keys[175].group = 1;
g->keys[176].group = 1;
g->keys[177].group = 1;
g->keys[178].group = 1;
g->keys[179].group = 1;
g->keys[180].group = 1;

g->keys[181].group = 1;
g->keys[182].group = 1;
g->keys[183].group = 1;
g->keys[184].group = 1;
g->keys[185].group = 1;
g->keys[186].group = 1;
g->keys[187].group = 1;
g->keys[188].group = 1;
g->keys[189].group = 1;
g->keys[190].group = 1;

g->keys[191].group = 1;
g->keys[192].group = 1;
g->keys[193].group = 1;
g->keys[194].group = 1;
g->keys[195].group = 1;
g->keys[196].group = 1;
g->keys[197].group = 1;
g->keys[198].group = 1;
g->keys[199].group = 1;
g->keys[200].group = 1;

g->keys[201].group = 1;
g->keys[202].group = 1;
g->keys[203].group = 1;
g->keys[204].group = 1;
g->keys[205].group = 1;
g->keys[206].group = 1;
g->keys[207].group = 1;
g->keys[208].group = 1;
g->keys[209].group = 1;
g->keys[210].group = 1;

g->keys[211].group = 1;
g->keys[212].group = 1;
g->keys[213].group = 1;
g->keys[214].group = 1;
g->keys[215].group = 1;
g->keys[216].group = 1;
g->keys[217].group = 1;
g->keys[218].group = 1;
g->keys[219].group = 1;
g->keys[220].group = 1;

g->keys[221].group = 1;
g->keys[222].group = 1;
g->keys[223].group = 1;
g->keys[228].group = 1;

g->keys[232].group = 1;
g->keys[233].group = 1;
g->keys[234].group = 1;
g->keys[235].group = 1;
g->keys[236].group = 1;
g->keys[237].group = 1;
g->keys[238].group = 1;
g->keys[239].group = 1;
g->keys[240].group = 1;

g->keys[241].group = 1;
g->keys[242].group = 1;
g->keys[243].group = 1;
g->keys[244].group = 1;
g->keys[245].group = 1;
g->keys[246].group = 1;
g->keys[247].group = 1;
g->keys[248].group = 1;
g->keys[249].group = 1;
g->keys[250].group = 1;

g->keys[251].group = 1;
g->keys[252].group = 1;
g->keys[253].group = 1;
g->keys[254].group = 1;
g->keys[255].group = 1;
g->keys[256].group = 1;
g->keys[257].group = 1;
g->keys[258].group = 1;
g->keys[259].group = 1;
g->keys[260].group = 1;

g->keys[261].group = 1;
g->keys[262].group = 1;
g->keys[263].group = 1;
g->keys[264].group = 1;
g->keys[265].group = 1;
g->keys[267].group = 1;
g->keys[268].group = 1;
g->keys[269].group = 1;
g->keys[270].group = 1;

g->keys[271].group = 1;
g->keys[272].group = 1;
g->keys[273].group = 1;
g->keys[274].group = 1;
g->keys[275].group = 1;
g->keys[276].group = 1;
g->keys[277].group = 1;
g->keys[278].group = 1;
g->keys[279].group = 1;
g->keys[280].group = 1;

g->keys[281].group = 1;
g->keys[282].group = 1;
g->keys[283].group = 1;
g->keys[284].group = 1;

	return 0;
}

int print_keyboard( struct globals *g ) {

	int i;

	fprintf(stdout,"\n-----------------------------\n");
	for (i = 0; i < KEYMAP_SIZE; i++) {
		if ( g->keys[i].pressed == 0  && g->keys[i].group == 0) {
			if (*g->keys[0].name != '\0') fprintf(stdout, "%s ", g->keys[i].name);
		}
		if (i%10 == 0) fprintf(stdout,"\n");
	}

	return 0;
}
int dump_remaining( struct globals *g ) {

	int i;

	for (i = 0; i < KEYMAP_SIZE; i++) {
		if ( g->keys[i].pressed == 0 ) {
			if (*g->keys[i].name != '\0') {
				fprintf(stdout, "g->keys[%d].group = 1;\n", i);
			}
		}
		if (i%10 == 0) fprintf(stdout,"\n");
	}

	return 0;
}

int display_keys( struct globals *g ) {
	int i;
	int e;
   SDL_Rect r;
    r.w = KEY_WIDTH;
    r.h = KEY_HEIGHT;

    SDL_SetRenderDrawColor( g->renderer, 0, 0, 255, 255 );


	for (i = 0; i < KEYMAP_SIZE; i++) {
		if ( g->keys[i].pressed == 0 ) {
			if (g->keys[i].group == 0) {
				int texW = 0;
				int texH = 0;
				SDL_Color color = { 255, 255, 255 };
				SDL_Surface *surface = NULL;
				SDL_Texture *texture = NULL;

				r.x = KEY_SPACING + (i % KEYS_ACROSS) *( r.w +KEY_SPACING );
				r.y = KEY_SPACING + (i / KEYS_ACROSS) *( r.h +KEY_SPACING );
			   e = SDL_RenderFillRect( g->renderer, &r );
				surface = TTF_RenderText_Solid(g->font, g->keys[i].name, color);
				if (surface == NULL) {
					fprintf(stderr,"Error creating surface for text (%s)\n", SDL_GetError());
					exit(1);
				}
				texture = SDL_CreateTextureFromSurface(g->renderer, surface);
				SDL_QueryTexture(texture, NULL, NULL, &texW, &texH);
				SDL_Rect dstrect = { r.x +KEY_PADDING, r.y +KEY_PADDING, texW, texH };
				SDL_RenderCopy(g->renderer, texture, NULL, &dstrect);
				SDL_DestroyTexture(texture);
				SDL_FreeSurface(surface);
				if (e < 0) {
					fprintf(stderr,"Error drawing rectangle (%s)\n", SDL_GetError());
				}
			}
		}
	}

    SDL_SetRenderDrawColor( g->renderer, 255, 255, 255, 255 );

	return 0;
}

int main(int argc, char **args) {
	struct globals glb, *g;
	int quit = 0;
	SDL_Event e;

	g = &glb;

	init(g);


	if (SDL_Init(SDL_INIT_VIDEO) < 0) {
		fprintf(stderr, "could not initialize sdl2: %s\n", SDL_GetError());
		return 1;
	}

	g->window = SDL_CreateWindow(
			"Keyboard Tester",
			SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
			SCREEN_WIDTH, SCREEN_HEIGHT,
			SDL_WINDOW_SHOWN
			);
	if (g->window == NULL) {
		fprintf(stderr, "could not create window: %s\n", SDL_GetError());
		return 1;
	}

//	g->screenSurface = SDL_GetWindowSurface(g->window);

   // Setup renderer
   g->renderer =  SDL_CreateRenderer( g->window, -1, SDL_RENDERER_SOFTWARE);
	if (g->renderer == NULL) {
		fprintf(stderr,"Error creating renderer (%s)\n", SDL_GetError());
		exit(1);
	}

    // Set render color to red ( background will be rendered in this color )
    SDL_SetRenderDrawColor( g->renderer, 255, 255, 255, 255 );

    // Clear winow
    SDL_RenderClear( g->renderer );

	display_keys(g);

	//While application is running
	while( !quit ) {

		SDL_Keymod ms;

		//Handle events on queue
		while( SDL_PollEvent( &e ) != 0 ) {

			if( e.type == SDL_QUIT ) {
				quit = 1;
			}


			ms = SDL_GetModState();

			if ( e.type == SDL_KEYDOWN ) {
				g->keys[e.key.keysym.scancode].pressed = 1;
//				print_keyboard(g);
				SDL_RenderClear( g->renderer );
				display_keys(g);
				if ( ms &  KMOD_ALT ) {
					if (e.key.keysym.scancode == SDL_SCANCODE_Q) {
						dump_remaining(g);
						quit = 1;
						break;
					}
				}
			}

		}
		SDL_RenderPresent( g->renderer );

	}

	SDL_DestroyWindow(g->window);
	SDL_Quit();

	return 0;
}

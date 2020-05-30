#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "font.h" // embedded fonts now, created using xxd -i <font> > font.h


#define PATH_MAX 4096

#define KEYMAP_SIZE 285 // how many actual keyboard scancodes there are that SDL2 recognises

#define DEFAULT_DPI 72
#define DEFAULT_FONT_SIZE 16
#define DEFAULT_KEY_WIDTH FONT_SIZE_DEFAULT *5
#define DEFUALT_KEY_HEIGHT DEFAULT_FONT_SIZE +10 
#define DEFAULT_KEY_SPACING FONT_SIZE_DEFAULT /6
#define DEFAULT_KEYS_ACROSS 16
#define DEFAULT_KEYS_DOWN 20
#define DEFAULT_KEY_PADDING FONT_SIZE_DEFAULT /7
#define DEFAULT_SCREEN_WIDTH (KEY_WIDTH +KEY_SPACING) *KEYS_ACROSS +KEY_SPACING
#define DEFAULT_SCREEN_HEIGHT (KEY_HEIGHT +KEY_SPACING) *KEYS_DOWN +KEY_SPACING

#define FL __FILE__,__LINE__



struct key {
	char *name;
	int pressed;
	int group;
	int x, y;
	uint32_t down, up, delta;
	uint32_t flagged;
};


struct globals {


	int key_width;
	int key_height;
	int key_spacing;
	int keys_across;
	int keys_down;
	int key_padding;

	int screen_width;
	int screen_height;

	struct key keys[KEYMAP_SIZE];
	int max_index;
	char *map_filename;
	int quit_on_complete;
	int any_unpressed;

	SDL_Window *window;
	SDL_Renderer *renderer;
	TTF_Font *font;
	int font_size;
	int font_size_px; // DPI converted font size
	int dpi;

	// Thresholds for testing
	//
	int dwell_lower;
	int dwell_upper; 
};


int map_default( struct globals *g ) {

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
	g->keys[41].name = "ESC";
	g->keys[42].name = "BACKSPACE";

	g->keys[43].name = "TAB";
	g->keys[44].name = "SPACE";
	g->keys[45].name = "-";
	g->keys[46].name = "=";

	g->keys[47].name = "(";
	g->keys[48].name = ")";
	g->keys[49].name = "\\";
	g->keys[50].name = "NONUSHASH";

	g->keys[51].name = ";";
	g->keys[52].name = "!";
	g->keys[53].name = "`";
	g->keys[54].name = ",";

	g->keys[55].name = ".";
	g->keys[56].name = "/";
	g->keys[57].name = "CAPS";
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
	g->keys[70].name = "PRNTSCR";

	g->keys[71].name = "SCROLLLOCK";
	g->keys[72].name = "PAUSE";
	g->keys[73].name = "INSERT";
	g->keys[74].name = "HOME";

	g->keys[75].name = "PGUP";
	g->keys[76].name = "DEL";
	g->keys[77].name = "END";
	g->keys[78].name = "PGDN";

	g->keys[79].name = "RIGHT";
	g->keys[80].name = "LEFT";
	g->keys[81].name = "DOWN";
	g->keys[82].name = "UP";

	g->keys[83].name = "NUMLOCKCLEAR";
	g->keys[84].name = "KP_/";
	g->keys[85].name = "KP_*";
	g->keys[86].name = "KP_-";

	g->keys[87].name = "KP_+";
	g->keys[88].name = "KP_ENT";
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

	g->keys[99].name = "KP_.";
	g->keys[100].name = "NONUSBACKSLASH";
	g->keys[101].name = "APP";
	g->keys[102].name = "POWER";

	g->keys[103].name = "KP_=";
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
	g->keys[128].name = "VOLUP";
	g->keys[129].name = "VOLDN";
	g->keys[133].name = "KP_,";

	g->keys[134].name = "KP_=";
	g->keys[135].name = "INTL1";
	g->keys[136].name = "INTL2";
	g->keys[137].name = "INTL3";

	g->keys[138].name = "INTL4";
	g->keys[139].name = "INTL5";
	g->keys[140].name = "INTL6";
	g->keys[141].name = "INTL7";

	g->keys[142].name = "INTL8";
	g->keys[143].name = "INTL9";
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
	g->keys[182].name = "KP_(";
	g->keys[183].name = "KP_)";
	g->keys[184].name = "KP_{";

	g->keys[185].name = "KP_}";
	g->keys[186].name = "KP_TAB";
	g->keys[187].name = "KP_BKSPC";
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
	g->keys[258].name = "AUNEXT";
	g->keys[259].name = "AUPREV";

	g->keys[260].name = "AUSTOP";
	g->keys[261].name = "AUPLAY";
	g->keys[262].name = "AUMUTE";
	g->keys[263].name = "MEDIASEL";

	g->keys[264].name = "WWW";
	g->keys[265].name = "MAIL";
	g->keys[266].name = "CALC";
	g->keys[267].name = "COMPTR";

	g->keys[268].name = "SEARCH";
	g->keys[269].name = "HOME";
	g->keys[270].name = "BACK";
	g->keys[271].name = "FORWARD";

	g->keys[272].name = "STOP";
	g->keys[273].name = "REFRESH";
	g->keys[274].name = "BOOKMARKS";
	g->keys[275].name = "BRIGHTDN";

	g->keys[276].name = "BRIGHTUP";
	g->keys[277].name = "DISPSW";
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

	g->max_index = 284;

	return 0;
}

int init_font( struct globals *g ) {

	g->font_size_px = g->font_size *g->dpi / 72;

	TTF_Init();
	SDL_RWops *fnt;
	fnt = SDL_RWFromMem( font_ttf, sizeof(font_ttf) );
	g->font = TTF_OpenFontRW( fnt, 0, g->font_size );
	if (g->font == NULL) {
		fprintf(stderr, "error: font not loaded\n");
		exit(EXIT_FAILURE);
	}

	return 0;

}

int init_layout( struct globals *g ) {

	g->key_padding = g->font_size /7;
	g->key_width = g->font_size *5;
	g->key_height = g->font_size +(2 *g->key_padding);
	g->key_spacing = g->font_size /6;
	g->keys_across = DEFAULT_KEYS_ACROSS;
	g->keys_down = DEFAULT_KEYS_DOWN;
	
	g->screen_width = (g->key_width +g->key_spacing) *g->keys_across +g->key_spacing;
	g->screen_height = (g->key_height +g->key_spacing) *g->keys_down +g->key_spacing;

	return 0;
}


int init( struct globals *g ) {

	int i;
	float f;

	g->window = NULL;
	g->renderer = NULL;
	g->map_filename = NULL;
	g->quit_on_complete = 0;

	i = SDL_GetDisplayDPI( 0, &f, NULL, NULL );
	if (i != 0) g->dpi = DEFAULT_DPI;
	else g->dpi = floor(f);
	g->font_size = DEFAULT_FONT_SIZE;


	// Initialise the scancode array with
	// all flagged as untouched
	//
	//
	for (i = 0; i < KEYMAP_SIZE; i++) {
		g->keys[i].pressed = 0;
		g->keys[i].name = NULL;
		g->keys[i].group = 0;
		g->keys[i].x = 0;
		g->keys[i].y = 0;
		g->keys[i].flagged = 0;
	}

	g->dwell_lower = 20; // anything shorter and probably not making full contact
	g->dwell_upper = 200; // anything longer and key is slow to return



	return 0;
}


int show_help( void ) {

	fprintf(stdout, "keyboard-tester [--dl <lower bound ms>] [--dh <upper bound ms>] [-m <mapfile>] [-c] [--dpi <dpi>] [--fs <pts>]\n"
			"\n"
			"--dl <time (20 ms default)> : Set acceptable lower limit of key down time\n"
			"--dh <time (200 ms default)> : Set acceptable upper limit of key down time\n"
			"-m <mapfile> : Set keyboard map to use, limits keys and sets names to test\n"
			"-c : Close tester when all keys have been pressed\n"
			"\n"
			"--dpi <dpi> : Force screen DPI\n"
			"--fs <pts> : Set font size in pts\n"
			"\n"
			"\tALT/OPT-Q: exit/quit\n"
			"\tALT/OPT-M: Save current pressed keyset to mapfile\n"
			"\n"
			);



	return 0;
}

int parse_parameters( struct globals *g, int argc, char **argv ) {

	int i;
	char *p;

	for (i = 1; i < argc; i++ ) {

		p = argv[i];

		if (strcmp( p, "-h" )==0) {
			show_help();
			exit(0);
		} 

		else if (strcmp( p, "-c")==0) {
			g->quit_on_complete = 1;
		}

		else if (strcmp( p, "-m")==0) {
			i++;
			g->map_filename = argv[i];
		}

		else if (strcmp( p, "--fs" )==0) {
			i++;
			g->font_size = strtol( argv[i], NULL, 10 );
			if (g->font_size < 4) g->font_size = 4;
			if (g->font_size > 40) g->font_size = 40;
		}

		else if (strcmp( p, "--dpi" )==0) {
			i++;
			g->dpi = strtol( argv[i], NULL, 10 );
			if (g->dpi < 70) g->dpi = 70;
			if (g->dpi > 200) g->dpi = 200;
		}

		else if (strcmp( p, "--dl" )==0) {
			i++;
			g->dwell_lower = strtol( argv[i], NULL, 10 );
		}

		else if (strcmp( p, "--dh" )==0) {
			i++;
			g->dwell_upper = strtol( argv[i], NULL, 10 );

		}

		else {
			fprintf(stderr,"Unknown parmeter '%s'\n", argv[i]);
		}

	} // for

	return 0;
} // parse paramters


int print_keyboard( struct globals *g ) {

	int i;

	fprintf(stdout,"\n-----------------------------\n");
	for (i = 0; i <= g->max_index; i++) {
		if ( g->keys[i].pressed == 0  && g->keys[i].group == 0) {
			if (*g->keys[i].name != '\0') fprintf(stdout, "%s ", g->keys[i].name);
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


int load_map( struct globals *g, char *fn ) {
	FILE *f;
	char s[1024];
	int idx, group;
	char name[21];

	f = fopen(fn, "r");
	if (f) {
		char *r;

		g->max_index = 0;
		while ((r = fgets(s, sizeof(s), f )) != NULL) {
			sscanf(s, "scancode:%d group:%d name:%20s\n", &idx, &group, name );
			g->keys[idx].group = group;
			g->keys[idx].name = strdup(name);
			if (idx > g->max_index) g->max_index = idx;
		}

		fclose(f);
	}
	return 0;
}


int save_map( struct globals *g ) {

	int i;
	FILE *f;
	char fn[PATH_MAX];

	snprintf(fn, sizeof(fn), "%ld.kmap", time(NULL));
	f = fopen(fn, "w");
	if (f) {

		fprintf(stdout,"Writing all currently pressed keys to '%s' ...", fn );

		for (i = 0; i <= g->max_index; i++) {
			if (g->keys[i].pressed == 2) {
				fprintf(stdout, "scancode:%d group:%d name:%s\n", i, g->keys[i].group, g->keys[i].name);
				fprintf(f, "scancode:%d group:%d name:%s\n", i, g->keys[i].group, g->keys[i].name);
			}
		}
		fclose(f);
		fprintf(stdout,"done.\n");
	}

	return 0;
}



int display_keys( struct globals *g ) {
	int i;
	SDL_Rect r;
	r.w = g->key_width;
	r.h = g->key_height;

	g->any_unpressed = 0;



	for (i = 0; i <= g->max_index; i++) {
		if (g->keys[i].name != NULL) {
			if ( g->keys[i].pressed < 2 ) {
				g->any_unpressed = 1;
				if (g->keys[i].pressed == 0) SDL_SetRenderDrawColor( g->renderer,  0, 0, 255, 255 );
				else if (g->keys[i].pressed == 1) SDL_SetRenderDrawColor( g->renderer, 255, 0, 0, 255);
				if (g->keys[i].group == 0) {
					int texW = 0;
					int texH = 0;
					SDL_Color color = { 255, 255, 255 };
					SDL_Surface *surface = NULL;
					SDL_Texture *texture = NULL;

					r.x = g->key_spacing+ (i % g->keys_across) *( r.w +g->key_spacing);
					r.y = g->key_spacing+ (i / g->keys_down) *( r.h +g->key_spacing);
					SDL_RenderFillRect( g->renderer, &r );
					surface = TTF_RenderText_Blended(g->font, g->keys[i].name, color);
					if (surface == NULL) {
						fprintf(stderr,"Error creating surface for text (%s)\n", SDL_GetError());
						exit(1);
					}
					texture = SDL_CreateTextureFromSurface(g->renderer, surface);
					SDL_QueryTexture(texture, NULL, NULL, &texW, &texH);
					//SDL_Rect dstrect = { r.x +g->key_padding, r.y +g->key_padding, texW, texH };
					SDL_Rect dstrect = { r.x, r.y, texW, texH };
					SDL_RenderCopy(g->renderer, texture, NULL, &dstrect);
					SDL_DestroyTexture(texture);
					SDL_FreeSurface(surface);
				} // if group 0

			} // if pressed < 2

			else {

				// leave behind stats of the key press
				//
				int texW = 0;
				int texH = 0;
				SDL_Color color = { 0, 0, 0 };
				SDL_Surface *surface = NULL;
				SDL_Texture *texture = NULL;
				char dwell[20];

				r.x = g->key_spacing+ (i % g->keys_across) *( r.w +g->key_spacing);
				r.y = g->key_spacing+ (i / g->keys_down) *( r.h +g->key_spacing);

				if (g->keys[i].flagged == 1) color.r = 255;
				snprintf(dwell, sizeof(dwell), "[%u]%s", g->keys[i].delta, g->keys[i].name );

				surface = TTF_RenderText_Blended(g->font, dwell, color);
				texture = SDL_CreateTextureFromSurface(g->renderer, surface);
				SDL_QueryTexture(texture, NULL, NULL, &texW, &texH);
				SDL_Rect dstrect = { r.x +g->key_padding, r.y +g->key_padding, texW, texH };
				SDL_RenderCopy(g->renderer, texture, NULL, &dstrect);
				SDL_DestroyTexture(texture);
				SDL_FreeSurface(surface);
			}

		}
	}

	SDL_SetRenderDrawColor( g->renderer, 255, 255, 255, 255 );

	return 0;
}

int main(int argc, char **argv) {
	struct globals glb, *g;
	int quit = 0;
	SDL_Event e;

	g = &glb;

	init(g);

	parse_parameters(g, argc, argv);

	init_font(g); // we have to do this after parsing paramters so that we can get a font size change if required

	init_layout(g); // work out all the sizes for the keys/padding/screen

	if (g->map_filename != NULL) {
		load_map(g, g->map_filename);
	} else {
		map_default(g);
	}


	if (SDL_Init(SDL_INIT_VIDEO) < 0) {
		fprintf(stderr, "could not initialize sdl2: %s\n", SDL_GetError());
		return 1;
	}

	g->window = SDL_CreateWindow(
			"Keyboard Tester",
			SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
			g->screen_width, g->screen_height,
			SDL_WINDOW_SHOWN
			);
	if (g->window == NULL) {
		fprintf(stderr, "could not create window: %s\n", SDL_GetError());
		return 1;
	}


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
		int sc;

		//Handle events on queue
		while( SDL_PollEvent( &e ) != 0 ) {

			if( e.type == SDL_QUIT ) {
				quit = 1;
			}


			ms = SDL_GetModState();
			sc = e.key.keysym.scancode;

			if ( e.type == SDL_KEYDOWN ) {
				g->keys[sc].pressed = 1;
				g->keys[sc].down = e.key.timestamp;
				SDL_RenderClear( g->renderer );
				display_keys(g);
				if ( ms &  KMOD_ALT ) {
					if (sc == SDL_SCANCODE_Q) {
						//						dump_remaining(g);
						quit = 1;
					}
					if (sc ==  SDL_SCANCODE_M) {
						save_map(g);
					}
				}
			} else if ( e.type == SDL_KEYUP ) {
				g->keys[sc].pressed = 2;
				g->keys[sc].up = e.key.timestamp;
				g->keys[sc].delta = g->keys[sc].up -g->keys[sc].down;
				if ((g->keys[sc].delta > g->dwell_upper)||(g->keys[sc].delta < g->dwell_lower)) g->keys[sc].flagged |= 1;
				SDL_RenderClear( g->renderer );
				display_keys(g);
				if (g->any_unpressed == 0 && g->quit_on_complete == 1) quit = 1;
			}

		}
		SDL_RenderPresent( g->renderer );


	}

	SDL_DestroyWindow(g->window);
	SDL_Quit();

	return 0;
}

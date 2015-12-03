/* 
 * Triforce ISO Extract
 * Copyright (C) 2015 FIX94
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <malloc.h>
#include <windows.h>
#include "des.h"

/* All the Triforce DES Keys I know */
#define KEYS_AVAIL 10
static const unsigned long long trikeys[KEYS_AVAIL] = {
	0xA82F6B8C6BC2158CULL, //F-Zero AX
	0xE0B9043E4C4F40BCULL, //Gekitou Pro Yakyuu
	0x2ADAE57FEF076D1AULL, //The Key of Avalon
	0xF2A24C7C6191E39DULL, //The Key of Avalon 2
	0x20FBD010E91AF4B3ULL, //Virtua Striker 3 Ver. 2002 (Japan)
	0x0B45139D91E0084FULL, //Virtua Striker 3 Ver. 2002 (Export)
	0x08BC388F76CB0231ULL, //Virtua Striker 4 (Japan)
	0x0BB58579C846C1DCULL, //Virtua Striker 4 (Export)
	0x83622ABF57DA1951ULL, //Virtua Striker 4 Ver. 2006 (Japan)
	0xABFBD902FBD980E5ULL, //Virtua Striker 4 Ver. 2006 (Export)
};

/* Triforce games are encrypted a little weird */
static inline void do64BitSwap(void *in, void *out)
{
	*(unsigned long long*)out = __builtin_bswap64(*(unsigned long long*)in);
}

/* Just a helper function for me to not get confused */
static inline void des_ecb_decrypt_swapped(struct _des_ctx *ctx, void *in, void *out) 
{
	do64BitSwap(in,out); //out is now the swapped input
	des_ecb_decrypt(ctx,out,out); //out is now swapped decrypted
	do64BitSwap(out,out); //out is now decrypted
}

static struct _des_ctx DESctx;
/* Use the GC Magic Word to verify DES key */
int findDESKey(unsigned char *buf)
{
	size_t i;
	unsigned char outbuf[8];
	unsigned char gcMagic[8] = { 0x00, 0x00, 0x00, 0x00, 0xC2, 0x33, 0x9F, 0x3D};
	for(i = 0; i < KEYS_AVAIL; i++)
	{
		des_setkey(&DESctx, (unsigned char*)(trikeys+i));
		des_ecb_decrypt_swapped(&DESctx, buf+0x18, outbuf);
		if(memcmp(outbuf, gcMagic, 8) == 0)
			return 1;
	}
	return 0;
}

/* Only 2048 bytes are actually data */
void decryptSector(unsigned char *in, unsigned char *out)
{
	size_t i;
	for(i = 0; i < 0x800; i+=8)
		des_ecb_decrypt_swapped(&DESctx, in+i, out+i);
}

#define ONE_MB 0x100000
int main(int argc, char *argv[])
{
	//windows exec path is so ugly to get
	char curpath[MAX_PATH]; 
	GetModuleFileName(NULL, curpath, MAX_PATH);
	char *pptr = curpath;
	while(*pptr) pptr++;
	while(*pptr != '\\') pptr--;
	*pptr = '\0';
	//lets actually do cool stuff
	puts("Triforce ISO Extract v1.0 by FIX94");
	if(argc != 2)
	{
		puts("No input file!");
		goto end_nofile;
	}
	FILE *f = NULL;
	if(strstr(argv[1],".chd") != NULL)
	{
		puts("CHD file mode");
		puts("Creating tmp directory...");
		mkdir("tmp");
		char fullpath[2048];
		puts("Calling chdman...\n");
		sprintf(fullpath,"\"\"%s\\chdman.exe\" extractraw -i \"%s\" -o tmp/raw.bin\"",curpath, argv[1]);
		system(fullpath);
		printf("\n");
		f = fopen("tmp/raw.bin","rb");
		if(!f)
		{
			puts("Unable to open raw.bin!");
			printf("The following command line was used:\n%s\n", fullpath);
			goto end_nofile;
		}
	}
	else
	{
		puts("Direct file mode\n");
		f = fopen(argv[1],"rb");
		if(!f)
		{
			printf("Unable to open %s!\n",argv[1]);
			goto end_nofile;
		}
	}
	fseek(f,0,SEEK_END);
	size_t fsize = ftell(f);
	if(fsize < ONE_MB)
	{
		puts("File too small!");
		goto end_file;
	}
	/* every image starts with SEGA so we can use that as offset */
	unsigned char inBuf[0x1000],outBuf[0x1000];
	puts("Trying to calculate file sector offset");
	fseek(f,0,SEEK_SET);
	fread(inBuf,1,0x810,f);
	size_t sec_offset;
	for(sec_offset = 0; sec_offset <= 0x800; ++sec_offset)
	{
		if(memcmp(inBuf+sec_offset,"SEGA",4) == 0 
			&& memcmp(inBuf+0x40+sec_offset,"GDT-",4) == 0)
		{
			printf("Found GD-ROM: %.9s\n",inBuf+0x40+sec_offset);
			break;
		}
	}
	if(sec_offset > 0x800)
	{
		puts("Invalid Sector Offset!");
		goto end_file;
	}
	printf("Sector Offset: 0x%x\n\n",sec_offset);

	puts("Trying to calculate sector size");
	size_t sec_size = 0x1001;
	size_t i,j,k, found = 0;
	for(i = 0x8000; i < 0x10000; i+=0xFF0)
	{
		fseek(f,i,SEEK_SET);
		fread(inBuf,1,0x1000,f);
		for(j = 0; j < 0x1000; j+=0x10)
		{
			if(memcmp(inBuf+j+1,"CD001",5) == 0)
			{
				printf("Known Sector Start: 0x%x\n",i+j-sec_offset);
				fseek(f,i+j+0x800,SEEK_SET);
				fread(inBuf,1,0x810,f);
				for(k = 0; k <= 0x800; k+=0x10)
				{
					if(memcmp(inBuf+k+1,"CD001",5) == 0)
					{
						sec_size = 0x800+k;
						printf("Known Sector End: 0x%x\n",i+j+sec_size-sec_offset);
						found = 1;
						break;
					}
				}
			}
			if(found) break;
		}
		if(found) break;
	}
	if(sec_size > 0x1000 || (sec_size - sec_offset) < 0x800)
	{
		puts("Invalid Sector Size!");
		goto end_file;
	}
	printf("Sector Size: %i bytes\n\n", sec_size);

	puts("Searching for GD-ROM Track 3");
	size_t start_pos = 0, readMax = fsize - 0x1000;
	found = 0;
	for(i = 0; i < readMax; i+=0xFFC)
	{
		fseek(f,i,SEEK_SET);
		fread(inBuf,1,0x1000,f);
		for(start_pos = 0; start_pos < 0xFFC; start_pos++)
		{
			if(memcmp(inBuf+start_pos,"TOC1",4) == 0)
			{
				puts("Found TOC string");
				found = 1;
				break;
			}
		}
		if(found) break;
	}
	if(!found || i >= readMax)
	{
		puts("GD-ROM Track 3 not found!");
		goto end_file;
	}
	size_t t3_start = (i+start_pos)-0x100-sec_offset;
	printf("GD-ROM Track 3 Start: 0x%08x\n\n", t3_start);

	puts("Trying to read file table");
	size_t gc_offset = 0;
	size_t gc_size = 0;
	char fOutName[0x100];
	//fixed? sector
	size_t fTableStart = t3_start+(0x14*sec_size);
	printf("File Table Start: 0x%08x\n", fTableStart);
	fseek(f,fTableStart+sec_offset,SEEK_SET);
	for(i = 0; i < 5; i++) //go through 5 reads
	{
		//this sector always provides its jump sizes
		unsigned char baseSize = 0;
		fread(&baseSize,1,1,f);
		if(baseSize == 0)
		{
			puts("Invalid file table read!");
			break;
		}
		//too small for file names etc
		if(baseSize > 1 && baseSize < 0x24)
		{
			fseek(f,baseSize-1,SEEK_CUR);
			continue;
		}
		fread(inBuf,1,baseSize-1,f);
		//file start sector
		gc_offset = __builtin_bswap32(*(unsigned int*)(inBuf+5));
		//file size in bytes
		gc_size = __builtin_bswap32(*(unsigned int*)(inBuf+13));
		//file size including ;1
		unsigned char fNameLen = *(inBuf+31);
		if(fNameLen > 2)
		{
			if(gc_size > ONE_MB)
			{
				memcpy(fOutName,inBuf+32,fNameLen-2);
				fOutName[fNameLen-1] = '\0';
				break;
			}
			else
				printf("Skipping over %.*s\n",fNameLen-2,inBuf+32);
		}
	}

	if((strstr(fOutName,".BIN") != NULL) || (strstr(fOutName,".GCM") != NULL))
	{
		printf("Goal file name: %s\n",fOutName);
		//really ugly calculation to skip over some sectors if needed
		gc_offset = (gc_offset*sec_size)+(t3_start-(45000*sec_size));
		//NOT sec_size because the usable data is always 0x800 bytes!
		size_t chunks_to_write = ((gc_size + 0x7FF) & ~0x7FF) / 0x800;
		printf("File Start: 0x%08x\nSize: %.02fMB\nChunks to write: %i\n",gc_offset,((float)gc_size)/1024.f/1024.f,chunks_to_write);
		if(gc_offset > 0 && gc_size > 0 && (gc_offset+(chunks_to_write*sec_size)) <= fsize)
		{
			fseek(f,gc_offset,SEEK_SET);
			fread(inBuf,1,sec_size,f);
			if(findDESKey(inBuf+sec_offset))
			{
				puts("Found Valid DES Key!\n");
				FILE *fOut = fopen(fOutName,"wb");
				if(!fOut)
				{
					puts("Unable to create file!");
					goto end_file;
				}
				printf("Writing file... 0%%");
				fseek(f,gc_offset,SEEK_SET);
				for(i = 0; i < chunks_to_write; i++)
				{
					fread(inBuf,1,sec_size,f);
					//make sure to think about the start offset!
					decryptSector(inBuf+sec_offset,outBuf);
					//only write actually valid data
					size_t towrite = (gc_size > 0x800) ? 0x800 : gc_size;
					fwrite(outBuf,1,towrite,fOut);
					gc_size -= 0x800;
					//inform the user about the progress from time to time
					if((i%0xFFF) == 0) printf("\rWriting file... %.0f%%",((float)i / (float)chunks_to_write)*100);
				}
				printf("\rWriting file... 100%%\n%s done!\n", fOutName);
				fclose(fOut);
			}
			else
				puts("Unable to find GC Magic!");
		}
		else
			puts("Invalid file!");
	}
	else
		puts("No .BIN found!");
end_file:
	fclose(f);
end_nofile:
	puts("Cleaning up tmp struct...");
	unlink("tmp/raw.bin");
	rmdir("tmp");
	puts("Press enter to exit");
	getc(stdin);
	return 0;
}

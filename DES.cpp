/*  A program that encrypts a file using the DES algorthim
     that has been implemented here in very basic level


      Created By ,   Anirban Das  anirban.nick@gmail.com
 
      2013

      How to use :
  
      type :
   
      $ DES -E filename.extension  (for Encrypting)
      $ DES -D fiename.des   (for Decrypting)

 -    you require the file to be encrypted along with a key.h file present in the directory
      you are running the program in , which contains the key you want to use to encrypt the file.

  -   you require the file to be decrypted along with a key.h file present in the directory
      you are running the program in , which contains the key that was used to encrypt the file you want
      to decrypt.

  NOTE : (1) the encrypted the file has .des extension
          
         (2) Thus, for decrypting the file should be a .des file
 
         (3) The key inside the  key.h file is nothing but a definition of an array in  c++ format

             eg: int key[64]= { 
                                 0,0,0,1,0,0,1,1,
                                 0,0,1,1,0,1,0,0,
                                 0,1,0,1,0,1,1,1,
                                 0,1,1,1,1,0,0,1,
                                 1,0,0,1,1,0,1,1,
                                 1,0,1,1,1,1,0,0,
                                 1,1,0,1,1,1,1,1,
                                 1,1,1,1,0,0,0,1 
                               }

*/
       
     



#include <iostream>
#include <stdio.h>
#include <fstream>
#include <stdlib.h>
#include <string.h>
//#include "key.h"

using namespace std;

int key[64]= {
	          0,0,0,1,0,0,1,1,
              0,0,1,1,0,1,0,0,
              0,1,0,1,0,1,1,1,
              0,1,1,1,1,0,0,1,
              1,0,0,1,1,0,1,1,
              1,0,1,1,1,1,0,0,
              1,1,0,1,1,1,1,1,
              1,1,1,1,0,0,0,1
		};


int size;
int blocksize = 8 ;
//int bs=blocksize*8;
char plainText[64],cypherText[64];
int c[28],d[28],pc1[56],KEY[16][48];
int L[32],R[32],R2[48],xor1[48],xor2[32],sub[32],p[32];

char *Encrypt(char *buffer);
char *Decrypt(char *buffer);
void keygen();
void permutedChoice1();
void leftShift(int n);
void permutedChoice2(int n);
void initialPermutation();
void encryptionRound(int n);
void F(int n);
void LxorF();
void expansion();
void R2xorKey(int n);
void substitutionBox();
void permutation();
void swap32bit();
void inversePermutation();



int main(int argc, char *argv[])
{ 
	ifstream input;
	ofstream output;	
	if(argc<3 || argc>3) 
	 {
	  printf("\n Correct no. of Arguments required :  DES -E(-D) filename \n");
	  return 1;      
	 }
	
	if ( (strcmp(argv[1],"-E")!=0) || (strcmp(argv[1],"-D")!=0) )
	{
		printf("\n%s no such valid argument known\n", argv[1]);
		return 1;      
	}

	if ( ( (strcmp(argv[1],"-D")==0) && (strstr(argv[2],".des")==NULL) ) ||  ( (strcmp(argv[1],"-E")==0) && (strstr(argv[2],".des")!=NULL) ) )
	{
		printf("\n-D with .des file\n-E with non .des file\n");
		return 1;      
	}
	
   
   if( strcmp(argv[1],"-E")==0)
   {
	    int len;
        char *bufferI, *bufferO;

        len=strlen(argv[2]);
		
	    char *filename=new char[len+4];
		
		strcpy(filename,argv[2]);
		filename[len++]='.';
		filename[len++]='d';
		filename[len++]='e';
		filename[len]='s';
		
 		input.open(argv[2], ios::in | ios::binary);
		output.open(filename, ios::out | ios::app);
 

    	input.seekg(0, ios::end);  // position get-ptr 0 bytes from end
    	size = input.tellg();  // get-ptr position is now same as file size
    	input.seekg(0, ios::beg);  // position get-ptr 0 bytes from beginning

    	bufferI = new char [size];
    	bufferO = new char [size];

    	input.read (bufferI,size);

		bufferO = Encrypt(bufferI);

    	output.write(bufferO,size);

 		// release dynamically-allocated memory
   		delete[] bufferI;
   		delete[] bufferO;

    }




    else
    {
	   
 
		char *bufferI, *bufferO,  *pos;
		char  *filename1;
		
		filename1=argv[2];
		int i=0;
		
		
		while(argv[2][i]!='.')
		{
			filename1[i]=argv[2][i];
			i++;
		}
		
		
	//	filename[i]='\0';
		
		
 		input.open(argv[2], ios::in | ios::binary);
		output.open(filename1, ios::out | ios::app);
 

    	input.seekg(0, ios::end);  // position get-ptr 0 bytes from end
    	size = input.tellg();  // get-ptr position is now same as file size
    	input.seekg(0, ios::beg);  // position get-ptr 0 bytes from beginning

    	bufferI = new char [size];
    	bufferO = new char [size];

    	input.read (bufferI,size);

 
		bufferO = Decrypt(bufferI);

    	
        output.write(bufferO,size);

 		// release dynamically-allocated memory
   		delete[] bufferI;
   		delete[] bufferO;

	
	
    }

	input.close();
	output.close();
	
	return 0;
	
	
}


char *Encrypt(char *buffer)
{
	int len,temp,i,j,k,ptr,ptr2,ptr3,ascii,index, binary[8];
    char *tempbuffer=new char[size];
	char *bufferO= new char[size];
    
    strcpy(tempbuffer,buffer);
    len=strlen(tempbuffer);
    temp = len % blocksize ;
    
    if(temp!=0) 
     {
	    for (i=0; i<(blocksize-temp); i++) 
	          tempbuffer[len++]= ' ' ;
     
        
        tempbuffer[len]='\0';
        len= strlen(tempbuffer);
      }



    keygen();
    
	
	ptr =0;
	ptr3=0;
    
    
    for( i=1; i<=(len/blocksize); i++) //Repeat for TextLenth/8 times.
    { 
		ptr2=0;
	    
        for(j=0; j< blocksize; j++)
        {
            ascii = (int) tempbuffer [ptr++];
			index=7;
            while(ascii>0)
            {
                binary[index--]=ascii % 2;  //Converting 8-Bytes to 64-bit Binary Format
                ascii= ascii/2;
            }
            

            while(index>=0)
				binary[index--] = 0;
            

            for(k=0; k<8; k++) 
                plainText[ptr2++]= binary [k]; //Now `total' contains the 64-Bit binary format of 8-Bytes
        
        }

      
        initialPermutation() ;

		for ( j =1 ; j<=16 ; j++)
		{
			encryptionRound(i) ;
		
		}
		
		
		swap32bit() ;
		
		inversePermutation() ;
		
		ptr2=0;
		index=7;
		ascii=0;
		
		 for(j=0; j< blocksize; j++)
        {
            for(k=0; k<8; k++)
            {
				ascii = ascii + cypherText[ptr2++]*index;
				index = index /2;
            }
            
            bufferO[ptr3++] = (char) ascii;
            
        }
    }


		return bufferO ;

}


char *Decrypt(char *buffer)
{
	int len,temp,i,j,k,ptr,ptr2,ptr3,ascii,index, binary[8];
    char *tempbuffer=new char[size];
	char *bufferO= new char[size];
    
    strcpy(tempbuffer,buffer);
    len=strlen(tempbuffer);
    temp = len % blocksize ;
    
    if(temp!=0) 
     {
	    for (i=0; i<(blocksize-temp); i++) 
	          tempbuffer[len++]= ' ' ;
     
        
        tempbuffer[len]='\0';
        len= strlen(tempbuffer);
      }



    keygen();
    
	
	ptr =0;
	ptr3=0;
    
    
    for( i=1; i<=(len/blocksize); i++) //Repeat for TextLenth/8 times.
    { 
		ptr2=0;
	    
        for(j=0; j< blocksize; j++)
        {
            ascii = (int) tempbuffer [ptr++];
			index=7;
            while(ascii>0)
            {
                binary[index--]=ascii % 2;  //Converting 8-Bytes to 64-bit Binary Format
                ascii= ascii/2;
            }
            

            while(index>=0)
				binary[index--] = 0;
            

            for(k=0; k<8; k++) 
                plainText[ptr2++]= binary [k]; //Now `total' contains the 64-Bit binary format of 8-Bytes
        
        }

      
        initialPermutation() ;

		for ( j =1 ; j<=16 ; j++)
		{
			encryptionRound(i) ;
		
		}
		
		
		swap32bit() ;
		
		inversePermutation() ;
		
		ptr2=0;
		index=7;
		ascii=0;
		
		 for(j=0; j< blocksize; j++)
        {
            for(k=0; k<8; k++)
            {
				ascii = ascii + cypherText[ptr2++]*index;
				index = index /2;
            }
            
            bufferO[ptr3++] = (char) ascii;
            
        }
    }


		return bufferO ;
}


void keygen()
{
	int i;
	permutedChoice1();
	for(i=0;i<28;i++)
	{	
		c[i]=pc1[i];
		d[i+28]=pc1[i+28];
    }
	for(i=1;i<=16;i++)
	{
		if( (i==1) || (i==2) || (i==9) || (i==16) )
		{
			leftShift(1);
		}
		else
		{
			leftShift(2);
		}
		permutedChoice2(i);
	}
}



void permutedChoice1()
{
    int i,j;
	j=57;
    for(i=0; i<28; i++)
    {
        pc1[i]=key[j-1];
        if(j-8>0)   
            j=j-8;
        else      
            j=j+57;
    }
    j=63;
    for( i=28; i<52; i++)
    {
        pc1[i]=key[j-1];
        if(j-8>0)   
            j=j-8;
        else      
            j=j+55;
    }
    j=28;
    for(i=52; i<56; i++)
    {
        pc1[i]=key[j-1];
        j=j-8;
    }	
}



void leftShift(int n)
{
	int i,temp1,temp2;
	while(n>0)
	{   temp1=c[0];
		temp2=d[0];
		for(i=0;i<27;i++)
		{
			c[i]=c[i+1];
			d[i]=d[i+1];
		}
		c[27]=temp1;
		d[27]=temp2;
		n--;
	}
}
	


void permutedChoice2(int n)
{
	int i,pc2[56];
      
    for(i=0; i<28; i++)
    {   pc2[i]=c[i];
        pc2[i+28]=d[i];
    }
   
    KEY[n][0] = pc2[13];
    KEY[n][1] = pc2[16];
    KEY[n][2] = pc2[10];
    KEY[n][3] = pc2[23];
    KEY[n][4] = pc2[0];
    KEY[n][5] = pc2[4];
    KEY[n][6] = pc2[2];
    KEY[n][7] = pc2[27];
    KEY[n][8] = pc2[14];
    KEY[n][9] = pc2[5];
    KEY[n][10] = pc2[20];
    KEY[n][11] = pc2[9];
    KEY[n][12] = pc2[22];
    KEY[n][13] = pc2[18];
    KEY[n][14] = pc2[11];
    KEY[n][15] = pc2[3];
    KEY[n][16] = pc2[25];
    KEY[n][17] = pc2[7];
    KEY[n][18] = pc2[15];
    KEY[n][19] = pc2[6];
    KEY[n][20] = pc2[26];
    KEY[n][21] = pc2[19];
    KEY[n][22] = pc2[12];
    KEY[n][23] = pc2[1];
    KEY[n][24] = pc2[40];
    KEY[n][25] = pc2[51];
    KEY[n][26] = pc2[30];
    KEY[n][27] = pc2[36];
    KEY[n][28] = pc2[46];
    KEY[n][29] = pc2[54];
    KEY[n][30] = pc2[29];
    KEY[n][31] = pc2[39];
    KEY[n][32] = pc2[50];
    KEY[n][33] = pc2[46];
    KEY[n][34] = pc2[32];
    KEY[n][35] = pc2[47];
    KEY[n][36] = pc2[43];
    KEY[n][37] = pc2[48];
    KEY[n][38] = pc2[38];
    KEY[n][39] = pc2[55];
    KEY[n][40] = pc2[33];
    KEY[n][41] = pc2[52];
    KEY[n][42] = pc2[45];
    KEY[n][43] = pc2[41];
    KEY[n][44] = pc2[49];
    KEY[n][45] = pc2[35];
    KEY[n][46] = pc2[28];
    KEY[n][47] = pc2[31];
}
	
  
void initialPermutation() //Initial Permutation
{
    int i, temp=58;
	int ip[64];
    for(i=0; i<32; i++)
    {
        ip[i]= plainText[temp-1];
        if(temp-8>0) 
            temp=temp-8;
        else       
            temp=temp+58;
    }
    
    temp=57;
    for( i=32; i<64; i++)
    {
        ip[i]=plainText[temp-1];
        if(temp-8>0) 
            temp=temp-8;
        else       
            temp=temp+58;
    }

	for(i=0;i<64;i++)
	{
		plainText[i]=ip[i];
	}

}



void encryptionRound(int n)
{
	int i,j=0;
	for(i=0;i<32;i++)
		L[i]=plainText[j++];
	for(i=0;i<32;i++)
		R[i]=plainText[j++];
    F(n);
	LxorF();
	for(i=0;i<32;i++)
		plainText[i]= R[i];
		plainText[i+32] = xor2[i];
}


void F(int n)
{
	expansion();
	R2xorKey(n);
	substitutionBox();
	permutation();
}		


void LxorF()
{
	int i;
    for(i=0; i<32; i++)
        xor2[i]= L[i] ^ p[i];
}

void expansion()
{
	int i,j,k,exp[8][6];
	for(i=0;i<8;i++)
	{
		for ( j=0;j<6;j++)
		{
			if(j==0)
			    {
					k = 4*i;
					exp[i][j] = R[k-1];
			    }
			else 
			{   k++;
				exp[i][j]=R[k-1]; 	
			}
		}
	}
	exp[0][0]=R[0];
	exp[7][5]=R[31];
	
	k=0;
	for(i=0;i<8;i++)
	{
		for(j=0;j<6;j++)
		{
			R2[k++]=exp[i][j];
		}
	}
	    
}



void R2xorKey(int n)
{
	int i;
    for(i=0; i<48; i++)
        xor1[i]= R2[i] ^ KEY[n][i];
}


void substitutionBox()
{
//	int subBox1[4][16], subBox2[4][16] , subBox3[4][16] , subBox4[4][16] , subBox5[4][16] , subBox6[4][16] , subBox7[4][16] , subBox8[4][16];
	int subBox[8][6],b[4],i,j,k,m,n,value,row,col;

    int subBox1[4][16]=
    {
        14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
        0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
        4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
        15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
    };

   int subBox2[4][16]=
    {
        15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
        3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
        0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
        13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
    };

    int subBox3[4][16]=
    {
        10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
        13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
        13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
        1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
    };

    int subBox4[4][16]=
    {
        7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
        13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
        10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
        3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
    };

    int subBox5[4][16]=
    {
        2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
        14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
        4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
        11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
    };

    int subBox6[4][16]=
    {
        12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
        10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
        9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
        4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
    };

    int subBox7[4][16]=
    {
        4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
        13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
        1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
        6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
    };
    
    int subBox8[4][16]=
    {
        13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
        1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
        7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
        2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
    };
    
	k=0;
	n=0;
    for(i=0; i<8; i++)
    {
        for(j=0; j<6; j++)
        {
            subBox[i][j]= xor1[k++];
        }
		
		row = (subBox[i][0]*2) + subBox[i][5];
		col = (subBox[i][1]*8) + (subBox[i][1]*4) + (subBox[i][1]*2) + (subBox[i][1]*1);
	 
	    if(i==0)
			value = subBox1[row][col];
	    else if(i==1)
			value = subBox2[row][col];
        else if(i==2)
			value = subBox3[row][col];	
		else if(i==3)
			value = subBox4[row][col];
		else if(i==4)
			value = subBox5[row][col];
		else if(i==5)
			value = subBox6[row][col];
		else if(i==6)
			value = subBox7[row][col];
		else if(i==7)
			value = subBox8[row][col];
			
		m=3;	
	    while(value>0)
	    {
			b[m] = value%2;
			value = value/2;
			m--;
		}
		
		while(m>=0)
		{
			b[m]=0;
			m--;
		}
		
		for(j=0;j<4;j++)
		{
			sub[n++]=b[j];
		}
	
	}
	
}



void permutation()
{
	p[0]=sub[15];
    p[1]=sub[6];
    p[2]=sub[19];
    p[3]=sub[20];
    p[4]=sub[28];
    p[5]=sub[11];
    p[6]=sub[27];
    p[7]=sub[16];
    p[8]=sub[0];
    p[9]=sub[14];
    p[10]=sub[22];
    p[11]=sub[25];
    p[12]=sub[4];
    p[13]=sub[17];
    p[14]=sub[30];
    p[15]=sub[9];
    p[16]=sub[1];
    p[17]=sub[7];
    p[18]=sub[23];
    p[19]=sub[13];
    p[20]=sub[31];
    p[21]=sub[26];
    p[22]=sub[2];
    p[23]=sub[8];
    p[24]=sub[18];
    p[25]=sub[12];
    p[26]=sub[29];
    p[27]=sub[5];
    p[28]=sub[21];
    p[29]=sub[10];
    p[30]=sub[3];
    p[31]=sub[24];
	
}


void swap32bit()
{   
	int i;
	for(i=0;i<32;i++)
	{ 
		L[i]=plainText[i];
		R[i]=plainText[i+32];
	}
	for(i=0;i<32;i++)
	{
		plainText[i]=R[i];
		plainText[i+32]=L[i];
	}
}


void inversePermutation()
{
	int i,j,k,a=40,b=8,c,d;
	int invP[blocksize][8];
    for(i=0; i<blocksize; i++)
    {
		c=a;
		d=b;
        for(j=0; j<8; j++)
        {
            if(j%2==0)
            {
                invP[i][j]=plainText[c-1];
                c=c+8;
            }
            else if(j%2!=0)
            {
                invP[i][j]=plainText[d-1];
                d=d+8;
            }
        }
        a=a-1;
        b=b-1;
    }
	
	k=0;
	for(i=0;i<blocksize;i++)
	{
		for(j=0;j<8;j++)
		{
			cypherText[k++] = invP[i][j];
		}
	}
}
 
     

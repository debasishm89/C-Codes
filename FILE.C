void main()
{
  int i;
  FILE *
  fp;
  char s[]="hello world";
  clrscr();
  fopen("f1.txt","w");
  if(fp==NULL)
  {
   printf("file not found");
   exit(0);
  }
   for(i=0;i<strlen(s);i++ )
   {
     fputc(s);
   }
   fclose(fp);
   getch();
}
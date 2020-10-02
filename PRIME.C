void main()
{
  int i=2,t=0,a=1;
  clrscr();
  while(a<=100)
  {
  while(a>i)
  {
    if(a%i==0)
    {
      t++;
      break;
    }
    i++;
  }
  if(t==0)
  {
    printf("%d\t",a);
  }
   a++;
   t=0;
   i=2;
  }
  getch();
}

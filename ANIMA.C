void main()
{
  int i=1;
  clrscr();
  while(i<=10)
  {
    gotoxy(37,12);
    printf("%d",i);
    delay(500);
    clrscr();
    i++;
  }
  gotoxy(34,12);
  printf("T");
  delay(500);

  gotoxy(35,12);
  printf("H");
  delay(500);

  gotoxy(36,12);
  printf("A");
  delay(500);

  gotoxy(37,12);
  printf("N");
  delay(500);

  gotoxy(38,12);
  printf("K");
  delay(500);

  gotoxy(39,12);
  printf("S");
  delay(500);

  getch();
}
#include<graphics.h>
void main()
{
 int gd= DETECT , gm;
 clrscr();
 initgraph(&gd,&gm,"c:\\Terboc3\\BGI");
 setfillstyle(SOLID FILL,RED);
 circle(200,200,100);
 floodfill(201,201,white);
 getch();
 closegraph();
}
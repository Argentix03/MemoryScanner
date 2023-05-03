#include <stdio.h>
#include <Windows.h>

typedef struct Player {
    int HP;
    int Mana;
    int Stamina;
} Player;
Player* players[100];

typedef struct Map {
    int visible;
    Player* players[100];

} Map;
Map map;

void hit(Player* p, int dmg);

int main()
{
    Player* p1 = (Player*) malloc(sizeof(Player));
    p1->HP = 100;
    p1->Mana = 200;
    p1->Stamina = 300;

    Player* p2 = (Player*) malloc(sizeof(Player));
    p2->HP = 100;
    p2->Mana = 200;
    p2->Stamina = 300;

    players[0] = p1;
    players[1] = p2;

    map.visible = 1;
    map.players[0] = p1;
    map.players[1] = p2;

    map.players[0]->HP = 1337;
    map.players[1]->HP = 1338;

    printf("Player 1: %p\n"
        "HP: %d Addr: %p\n"
        "Mana: %d Addr: %p\n"
        "Stamina: %d Addr: %p\n",
        p1,
        p1->HP, &(p1->HP),
        p1->Mana, &(p1->Mana),
        p1->Stamina, &(p1->Stamina)
    );
    printf("Player 2: %p\n"
        "HP: %d Addr: %p\n"
        "Mana: %d Addr: %p\n"
        "Stamina: %d Addr: %p\n",
        p2,
        p2->HP, &(p2->HP),
        p2->Mana, &(p2->Mana),
        p2->Stamina, &(p2->Stamina)
    );

    printf("players[0]: %p\n", &players[0]);
    printf("players[1]: %p\n", &players[1]);
    printf("map: %p\n", &map);
    printf("map.players[0]: %p value: %p\n", &map.players[0], map.players[0]);
    printf("map.players[0]->HP: %p\n", &map.players[0]->HP);
    printf("map.players[1]: %p\n", &map.players[1]);
    printf("map.players[1]->HP: %p\n", &map.players[1]->HP);

    system("pause");

    hit(p1, 100);
    hit(p2, 200);
    hit(map.players[0], 100);
    hit(map.players[1], 200);

    printf("Player 1: %p\n"
        "HP: %d Addr: %p\n"
        "Mana: %d Addr: %p\n"
        "Stamina: %d Addr: %p\n",
        p1,
        p1->HP, &(p1->HP),
        p1->Mana, &(p1->Mana),
        p1->Stamina, &(p1->Stamina)
    );
    printf("Player 2: %p\n"
        "HP: %d Addr: %p\n"
        "Mana: %d Addr: %p\n"
        "Stamina: %d Addr: %p\n",
        p2,
        p2->HP, &(p2->HP),
        p2->Mana, &(p2->Mana),
        p2->Stamina, &(p2->Stamina)
    );

    return 0;
}

void hit(Player* p, int dmg)
{
    p->HP -= dmg;
}
#include <stdio.h>
#include <Windows.h>

#define MAX_PLAYERS 10

enum BuffType {
    fire,
    frost,
    damageBoost,
    fireResistence
};

enum ItemType {
    weapon,
    consumable,
    questItem,
    armour
};

typedef struct Item {
    const char* name;
    ItemType type;
    bool isEquipped;
    int quantity;
    int activeBuff;
    int damage;
    int defence;
} Item;

typedef struct Slot {
    int id;
    bool isActive;
    Item* item;
} Slot;

typedef struct Player {
    int HP;
    int Mana;
    int Stamina;
    Slot slots[10];
    const char* name;
} Player;

typedef struct Map {
    int visible;
    Player* players[MAX_PLAYERS];
} Map;

Map g_map;
Player* g_players[10];


void hit(Player* p, int dmg);
void printPlayerInfo(Player* p);
void printMapInfoPtr(Map* m);
void printMapInfo(Map m);

int main()
{
    // PID
    printf("PID: %d\n", GetCurrentProcessId());

    // Generate some items
    Item* swordOfIce = (Item*) malloc(sizeof(Item));
    swordOfIce->activeBuff = frost;
    swordOfIce->name = "Sword of true 0k ice";
    swordOfIce->damage = 30;
    swordOfIce->type = weapon;

    Item* hellblade = (Item*) malloc(sizeof(Item));
    hellblade->name = "Hellblade";
    hellblade->damage = 99;
    hellblade->type = weapon;
    hellblade->activeBuff = fire;

    Item* healthpot = (Item*) malloc(sizeof(Item));
    healthpot->name = "Health Potion";
    healthpot->damage = NULL;
    healthpot->type = consumable;
    healthpot->activeBuff = NULL;
    healthpot->quantity = 15;


    Item* kingArmour = (Item*) malloc(sizeof(Item));
    hellblade->name = "King's armour";
    hellblade->defence = 20;
    hellblade->type = armour;
    hellblade->activeBuff = fireResistence;

    // Generate some players
    Player* p1 = (Player*) malloc(sizeof(Player));
    p1->HP = 100;
    p1->Mana = 200;
    p1->Stamina = 300;
    p1->slots[0].item = swordOfIce;
    p1->slots[1].item = hellblade;
    p1->name = "Perseidi";

    Player* p2 = (Player*) malloc(sizeof(Player));
    p2->HP = 150;
    p2->Mana = 150;
    p2->Stamina = 300;
    p2->slots[0].item = healthpot;
    p2->slots[1].item = healthpot;
    p2->slots[2].item = healthpot;
    p2->slots[3].item = healthpot;
    p2->slots[4].item = healthpot;
    p2->name = "Argentix";

    Player* p3 = (Player*) malloc(sizeof(Player));
    p3->HP = 1000;
    p3->Mana = 2000;
    p3->Stamina = 3000;
    p3->slots[0].item = NULL;
    p3->slots[1].item = NULL;
    p3->name = "Bot 1";

    Player* p4 = (Player*) malloc(sizeof(Player));
    p4->HP = 1000;
    p4->Mana = 2000;
    p4->Stamina = 3000;
    p4->slots[0].item = NULL;
    p4->slots[1].item = NULL;
    p4->name = "404 Name not found";

    // Some random players in global variables
    g_players[0] = p1;
    g_players[1] = p2;

    // A map that is a global variable
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        g_map.players[i] = NULL;
    }
    g_map.visible = 1;
    g_map.players[0] = p1;
    g_map.players[1] = p2;
    g_map.players[0]->HP = 1337;
    g_map.players[1]->HP = 1338;

    // Generate map (dyanmic map on the heap, later will add a reference to it somewhere with rva to some module)
    Map* map = (Map*) malloc(sizeof(Map));
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        map->players[i] = NULL;
    }
    map->visible = 1;
    map->players[0] = p3;
    map->players[1] = p4;
    map->players[0]->HP = 1337;
    map->players[1]->HP = 1338;

    // Print some info
    printPlayerInfo(p1);
    printPlayerInfo(p2);

    // stack local player
    void* local_ptr_p1 = &p1;
    printf("local_ptr_p1: %p\n", &local_ptr_p1);

    //// some player info
    //printf("g_players[0]: %p\n", &g_players[0]);
    //printf("g_players[1]: %p\n", &g_players[1]);
    //printf("g_map: %p\n", &g_map);
    //printf("g_map.players[0]: %p value: %p\n", &g_map.players[0], g_map.players[0]);
    //printf("g_map.players[0]->HP: %p\n", &g_map.players[0]->HP);
    //printf("g_map.players[1]: %p\n", &g_map.players[1]);
    //printf("g_map.players[1]->HP: %p\n", &g_map.players[1]->HP);

    //// some map info
    //printf("map: %p\n", &map);
    //printf("map->players[0]: %p value: %p\n", &map->players[0], map->players[0]);
    //printf("map->players[0]->HP: %p\n", &map->players[0]->HP);
    //printf("map->players[1]: %p\n", &map->players[1]);
    //printf("map->players[1]->HP: %p\n", &map->players[1]->HP);


    // full map info
    printMapInfoPtr(map);
    printMapInfo(g_map);

    system("pause");

    hit(p1, 100);
    hit(p2, 200);
    hit(g_map.players[0], 100);
    hit(g_map.players[1], 200);
    map->players[2] = p3;
    map->players[3] = p4;

    printf("info p1:\n");
    printPlayerInfo(p1);
    printf("info p2:\n");
    printPlayerInfo(p2);

    printf("heap map:\n");
    printMapInfoPtr(map);

    printf("global g_map:\n");
    printMapInfo(g_map);

    return 0;
}

void hit(Player* p, int dmg)
{
    p->HP -= dmg;
}

void printPlayerInfo(Player* p)
{
    if (!p)
        return;

    printf("Player: %p Addr: %p\n"
        "Name: \"%s\" Addr: %p\n"
        "HP: %d Addr: %p\n"
        "Mana: %d Addr: %p\n"
        "Stamina: %d Addr: %p\n",
        p, &p,
        p->name, &(p->name),
        p->HP, &(p->HP),
        p->Mana, &(p->Mana),
        p->Stamina, &(p->Stamina)
    );
}

void printMapInfoPtr(Map* m)
{
    if (!m)
        return;

    printf("Map visisble: %s\n", m->visible ? "True" : "False");
    printf("Players:\n");
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        if (!m->players[i])
            return;

        printPlayerInfo(m->players[i]);
    }
}

void printMapInfo(Map m)
{
    printf("Map visisble: %s\n", m.visible ? "True" : "False");
    printf("Players:\n");
    for (int i = 0; i < MAX_PLAYERS; ++i) {
        if (!m.players[i])
            return;

        printPlayerInfo(m.players[i]);
    }
}
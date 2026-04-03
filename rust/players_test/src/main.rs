//! Port of PlayersTests/PlayersTests.cpp
//! A test target with complex struct layouts for pointer-scan testing.

#![allow(dead_code, unused_variables)]

use std::io::{self, Write};
use std::process;

const MAX_PLAYERS: usize = 10;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum BuffType {
    NullBuf = 0,
    Fire,
    Frost,
    DamageBoost,
    FireResistence,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum ItemType {
    Weapon,
    Consumable,
    QuestItem,
    Armour,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Modifier {
    DoubleDamage,
    DoubleResistence,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum SkillId {
    CallOfTheForgeGod = 487253361,
    PlacidusaxRuin = 487253322,
    BlessingOfTheErdtree = 487253377,
}

#[repr(C)]
struct Skill {
    name: *const i8,
    id: SkillId,
    level: i32,
    cast_skill: Option<unsafe extern "C" fn(i32) -> bool>,
}

#[repr(C)]
struct Item {
    name: *const i8,
    item_type: ItemType,
    is_equipped: bool,
    quantity: i32,
    active_buff: BuffType,
    damage: i32,
    defence: i32,
    active_skill: *mut Skill,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Slot {
    id: i32,
    is_active: bool,
    item: *mut Item,
}

#[repr(C)]
struct Player {
    hp: i32,
    mana: i32,
    stamina: i32,
    slots: [Slot; 10],
    active_slot: Slot,
    name: *const i8,
}

#[repr(C)]
struct Map {
    visible: i32,
    players: [*mut Player; MAX_PLAYERS],
}

// Global variables — mirror C++ globals
static mut G_MAP: Map = Map {
    visible: 0,
    players: [std::ptr::null_mut(); MAX_PLAYERS],
};
static mut G_PLAYERS: [*mut Player; 10] = [std::ptr::null_mut(); 10];

fn flush() {
    let _ = io::stdout().flush();
}

fn pause() {
    print!("Press Enter to continue...");
    flush();
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

unsafe fn hit(p: *mut Player, dmg: i32) {
    if p.is_null() {
        println!("nullplayer");
        return;
    }
    (*p).hp -= dmg;
}

unsafe fn print_player_info(p: *const Player) {
    if p.is_null() {
        return;
    }
    let name = std::ffi::CStr::from_ptr((*p).name).to_string_lossy();
    println!(
        "Player: {:p} Addr: {:p}\nName: \"{}\" Addr: {:p}\nHP: {} Addr: {:p}\nMana: {} Addr: {:p}\nStamina: {} Addr: {:p}",
        p, &p,
        name, &(*p).name,
        (*p).hp, &(*p).hp,
        (*p).mana, &(*p).mana,
        (*p).stamina, &(*p).stamina,
    );
}

unsafe fn print_map_info_ptr(m: *const Map) {
    if m.is_null() {
        println!("Nullmap");
        return;
    }
    println!("Map addr: {:p}", m);
    println!("Map visisble: {}", if (*m).visible != 0 { "True" } else { "False" });
    println!("Players:");
    for i in 0..MAX_PLAYERS {
        if (*m).players[i].is_null() {
            println!("Nullplayer");
            return;
        }
        print_player_info((*m).players[i]);
    }
}

// Mirror of printMapInfo(Map m) — takes ownership by value (copy on the stack)
// In C++ this receives a copy of the Map struct; we match that by passing by value.
unsafe fn print_map_info(m: Map) {
    // The address printed here will be of the local copy, matching C++ behavior.
    let m_ref = &m;
    println!("Map addr (probably stack local for this fn): {:p}", m_ref);
    println!("Map visisble: {}", if m.visible != 0 { "True" } else { "False" });
    println!("Players:");
    for i in 0..MAX_PLAYERS {
        print_player_info(m.players[i]);
    }
}

fn main() {
    println!("PID: {}", process::id());

    unsafe {
        // Generate some items (heap allocated, matching malloc in C++)
        let sword_of_ice = Box::into_raw(Box::new(Item {
            name: b"Sword of true 0k ice\0".as_ptr() as *const i8,
            active_buff: BuffType::Frost,
            damage: 30,
            item_type: ItemType::Weapon,
            is_equipped: false,
            quantity: 0,
            defence: 0,
            active_skill: std::ptr::null_mut(),
        }));

        let weapon_skill = Box::into_raw(Box::new(Skill {
            id: SkillId::CallOfTheForgeGod,
            level: 99,
            name: b"Call of the Forge God\0".as_ptr() as *const i8,
            cast_skill: None,
        }));

        let hellblade = Box::into_raw(Box::new(Item {
            name: b"Hellblade\0".as_ptr() as *const i8,
            damage: 99,
            item_type: ItemType::Weapon,
            active_buff: BuffType::Fire,
            is_equipped: false,
            quantity: 0,
            defence: 0,
            active_skill: weapon_skill,
        }));

        let healthpot = Box::into_raw(Box::new(Item {
            name: b"Health Potion\0".as_ptr() as *const i8,
            damage: 0,
            item_type: ItemType::Consumable,
            active_buff: BuffType::NullBuf,
            quantity: 15,
            is_equipped: false,
            defence: 0,
            active_skill: std::ptr::null_mut(),
        }));

        // King's armour — note: C++ code mistakenly wrote hellblade->... instead of kingArmour->...
        // We replicate the same behavior (overwriting hellblade fields).
        let king_armour = Box::into_raw(Box::new(Item {
            name: b"King's armour\0".as_ptr() as *const i8, // original uses hellblade->name
            damage: 0,
            defence: 20,
            item_type: ItemType::Armour,
            active_buff: BuffType::FireResistence,
            is_equipped: false,
            quantity: 0,
            active_skill: std::ptr::null_mut(),
        }));
        // Replicate C++ bug: these writes go to hellblade, not king_armour
        (*hellblade).name = b"King's armour\0".as_ptr() as *const i8;
        (*hellblade).defence = 20;
        (*hellblade).item_type = ItemType::Armour;
        (*hellblade).active_buff = BuffType::FireResistence;

        // Generate some players
        let null_slot = Slot { id: 0, is_active: false, item: std::ptr::null_mut() };
        let p1 = Box::into_raw(Box::new(Player {
            hp: 100,
            mana: 200,
            stamina: 300,
            slots: [
                Slot { id: 0, is_active: false, item: sword_of_ice },
                Slot { id: 1, is_active: false, item: hellblade },
                null_slot, null_slot, null_slot,
                null_slot, null_slot, null_slot,
                null_slot, null_slot,
            ],
            active_slot: null_slot,
            name: b"Perseidi\0".as_ptr() as *const i8,
        }));

        let p2 = Box::into_raw(Box::new(Player {
            hp: 150,
            mana: 150,
            stamina: 300,
            slots: [
                Slot { id: 0, is_active: false, item: healthpot },
                Slot { id: 1, is_active: false, item: healthpot },
                Slot { id: 2, is_active: false, item: healthpot },
                Slot { id: 3, is_active: false, item: healthpot },
                Slot { id: 4, is_active: false, item: healthpot },
                null_slot, null_slot, null_slot,
                null_slot, null_slot,
            ],
            active_slot: null_slot,
            name: b"Argentix\0".as_ptr() as *const i8,
        }));

        let p3 = Box::into_raw(Box::new(Player {
            hp: 1000,
            mana: 2000,
            stamina: 3000,
            slots: [null_slot; 10],
            active_slot: null_slot,
            name: b"Bot 1\0".as_ptr() as *const i8,
        }));

        let p4 = Box::into_raw(Box::new(Player {
            hp: 1000,
            mana: 2000,
            stamina: 3000,
            slots: [null_slot; 10],
            active_slot: null_slot,
            name: b"404 Name not found\0".as_ptr() as *const i8,
        }));

        // Some random players in global variables
        G_PLAYERS[0] = p1;
        G_PLAYERS[1] = p2;

        // A map that is a global variable
        for i in 0..MAX_PLAYERS {
            G_MAP.players[i] = std::ptr::null_mut();
        }
        G_MAP.visible = 1;
        G_MAP.players[0] = p1;
        G_MAP.players[1] = p2;
        (*(*(&raw const G_MAP)).players[0]).hp = 1337;
        (*(*(&raw const G_MAP)).players[1]).hp = 1338;

        // Generate map (dynamic map on the heap)
        let map = Box::into_raw(Box::new(Map {
            visible: 1,
            players: [std::ptr::null_mut(); MAX_PLAYERS],
        }));
        (*map).players[0] = p3;
        (*map).players[1] = p4;
        (*(*map).players[0]).hp = 1337;
        (*(*map).players[1]).hp = 1338;
        (*map).players[2] = p1;

        // Print some info
        print_player_info(p1);
        print_player_info(p2);

        // Stack local pointer
        let local_ptr_p1: *mut Player = p1;
        println!("local_ptr_p1: {:p}", &local_ptr_p1);

        // Full map info
        print_map_info_ptr(map);
        // G_MAP passed by value — copy to stack, matching C++ printMapInfo(Map m)
        let g_map_copy = Map {
            visible: (*(&raw const G_MAP)).visible,
            players: (*(&raw const G_MAP)).players,
        };
        print_map_info(g_map_copy);

        pause();

        hit(p1, 100);
        hit(p2, 200);
        hit((*(&raw const G_MAP)).players[0], 100);
        hit((*(&raw const G_MAP)).players[1], 200);
        (*map).players[2] = p1;
        (*map).players[3] = p2;

        println!("info p1:");
        print_player_info(p1);
        println!("info p2:");
        print_player_info(p2);

        println!("heap map:");
        print_map_info_ptr(map);

        println!("global g_map:");
        let g_map_copy2 = Map {
            visible: (*(&raw const G_MAP)).visible,
            players: (*(&raw const G_MAP)).players,
        };
        print_map_info(g_map_copy2);

        use std::mem::offset_of;
        println!(
            "Potential pointer path (Recurse 2):\n\
             (Heap) map: {:p} + [offset 0x{:x}] -> players: {:p} + [offset 0x{:x}] *-> player: {:p} + [offset 0x{:x}] -> HP {:p}\n\
             map->players[1]->HP",
            map, offset_of!(Map, players),
            (*map).players.as_ptr(), std::mem::size_of::<Player>() * 1,
            (*map).players[1], offset_of!(Player, hp),
            &(*(*map).players[1]).hp
        );

        println!(
            "Potential pointer path (Recurse 2):\n\
             (Global) map: {:p} + [offset 0x{:x}] -> players: {:p} + [offset 0x{:x}] *-> player: {:p} + [offset 0x{:x}] -> HP {:p}\n\
             map->players[1]->HP",
            &raw const G_MAP, offset_of!(Map, players),
            (*(&raw const G_MAP)).players.as_ptr(), std::mem::size_of::<Player>() * 1,
            (*(&raw const G_MAP)).players[1], offset_of!(Player, hp),
            &(*(*(&raw const G_MAP)).players[1]).hp
        );

        println!(
            "Potential pointer path (Recurse 4):\n\
             (Heap) map: {:p} + [offset 0x{:x}] -> players: {:p} + [offset 0x{:x}] *-> player: {:p} + [offset 0x{:x}] -> slots {:p} + [offset 0x{:x}] *-> item in slot: {:p} + [offset 0x{:x}] *-> item skill: {:p} + [offset 0x{:x}] *-> skill identifier: {:p}\n\
             map->players[2]->slots[1].item->activeSkill->id",
            map, offset_of!(Map, players),
            (*map).players.as_ptr(), std::mem::size_of::<Player>() * 2,
            (*map).players[2], offset_of!(Player, slots),
            (*(*map).players[2]).slots.as_ptr(), std::mem::size_of::<Slot>() * 1,
            (*(*map).players[2]).slots[1].item, offset_of!(Item, active_skill),
            (*(*(*map).players[2]).slots[1].item).active_skill, offset_of!(Skill, id),
            &(*(*(*(*map).players[2]).slots[1].item).active_skill).id as *const SkillId
        );

        pause();

        G_MAP.players[2] = p1;
        println!("g_map: {:p}, value: {:p}", &raw const G_MAP, &raw const G_MAP);
        println!("g_map.players[2]: {:p}, value: {:p}", &raw const G_MAP.players[2], (*(&raw const G_MAP)).players[2]);
        println!("g_map.players[2]->slots[1]: {:p}, value: {:p}", &(*(*(&raw const G_MAP)).players[2]).slots[1], &(*(*(&raw const G_MAP)).players[2]).slots[1] as *const Slot);
        println!("g_map.players[2]->slots[1].item: {:p}, value: {:p}", &(*(*(&raw const G_MAP)).players[2]).slots[1].item, (*(*(&raw const G_MAP)).players[2]).slots[1].item);
        println!("g_map.players[2]->slots[1].item->activeSkill: {:p}, value: {:p}", &(*(*(*(&raw const G_MAP)).players[2]).slots[1].item).active_skill, (*(*(*(&raw const G_MAP)).players[2]).slots[1].item).active_skill);
        println!(
            "g_map.players[2]->slots[1].item->activeSkill->id: {:p}, value: {}",
            &(*(*(*(*(&raw const G_MAP)).players[2]).slots[1].item).active_skill).id,
            (*(*(*(*(&raw const G_MAP)).players[2]).slots[1].item).active_skill).id as i32
        );

        pause();
    }
}

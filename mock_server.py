from http.server import HTTPServer, BaseHTTPRequestHandler
import json, time, uuid, os
from datetime import datetime, timezone

CHARACTERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "characters.json")


def load_characters():
    if os.path.exists(CHARACTERS_FILE):
        try:
            with open(CHARACTERS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return []


def save_characters():
    with open(CHARACTERS_FILE, "w") as f:
        json.dump(saved_characters, f, indent=2)

# Only these fields are safe in a character list entry.  Extra fields cause the
# client's CharacterEntry deserializer to return null and crash.
CHARACTER_LIST_FIELDS = {
    "name", "object_guid", "archetype_name", "race_name", "gender_id",
    "level", "vessel_quality", "customization_tints", "customization_features",
    "equipment_items", "inventory_items", "vessel_talent_allocations",
    "vessel_stat_allocations", "vessel_stat_rewards",
}


def convert_tints(tints):
    """Convert create-request tint format to CharacterCustomizationTint format.
    {TintId, TintValues} -> {key, value: {masks_tints}}"""
    result = []
    for t in tints:
        if "key" in t:
            result.append(t)  # already in list format
        else:
            result.append({
                "key": t.get("TintId", 0),
                "value": {"masks_tints": t.get("TintValues", [])},
            })
    return result


def convert_features(features):
    """Convert create-request feature format to CharacterCustomizationFeature format.
    {FeatureId, Value} -> {key, value}"""
    result = []
    for f in features:
        if "key" in f:
            result.append(f)  # already in list format
        else:
            result.append({
                "key": f.get("FeatureId", 0),
                "value": f.get("Value", 0),
            })
    return result


def character_to_list_entry(char):
    entry = {k: char[k] for k in CHARACTER_LIST_FIELDS if k in char}
    if "customization_tints" in entry:
        entry["customization_tints"] = convert_tints(entry["customization_tints"])
    if "customization_features" in entry:
        entry["customization_features"] = convert_features(entry["customization_features"])
    return entry

saved_characters = load_characters()


def make_login_response():
    return {
        "access_token": "mock_access_token",
        "refresh_token": "mock_refresh_token",
        "platform_token": "mock_platform_token",
        "expires": "2099-12-31T00:00:00.000Z",
        "server_time_stamp": int(time.time()),
        "player_id": "00000000-0000-0000-0000-000000000001",
        "server_version": "develop-167-1b557011",
        "version_matches": "true",
        "username": "bearlikelion",
        "features": [],
        "storage_bonuses": {"account_bank": 0, "world_bank": 0},
        "guild_id": "",
        "guild_rank": 0,
        "lang_pref": "en",
        "demo_mode": False,
        "hd_only": False,
        "trial_days_remaining": 999,
        "character_slot_data": {
            "trial": 0, "normal": 8, "purchased": 0,
            "purchasable": 0, "can_purchase": False,
            "available": 8, "specials": []
        }
    }


def make_enter_lobby_response():
    active_character_guid = saved_characters[0]["object_guid"] if saved_characters else ""
    return {
        "success": True,
        "message": "",
        "queueToken": "mock_queue_token",
        "zoneRemoved": False,
        "canRecall": False,
        "inLobby": True,
        "characterGuid": active_character_guid,
        "currentScenarioUuid": "",
        "zoneInfo": {
            "endpoint": "127.0.0.1:8900",
            "ipv6_endpoint": "",
            "scene_name": "Lobby",
            "context_id": 1
        },
        "queueInfo": {
            "position": 0, "blocked": False,
            "blockedReason": "", "blockedLimit": 0
        }
    }


def make_bank_response():
    return {
        "Success": True,
        "Message": "",
        "Manifest": {
            "Items": [],
            "WorldBanks": [],
            "DeletedBanks": [],
            "AccountBank": {
                "BankGuid": "00000000-0000-0000-0000-000000000001",
                "Items": [],
                "ScenarioUUID": "",
                "ScenarioName": "",
                "ScenarioEndDate": "",
                "FactionId": 0,
                "MaxItemsStored": 200,
                "ImportTokensUsed": 0,
                "ExportTokensUsed": 0,
                "ScenarioActive": False,
                "EmbargoRules": {
                    "Locking": False,
                    "DefaultExportCount": 0,
                    "DefaultImportCount": 0,
                    "InventoryRestrictions": 0,
                    "AllowEarlyExport": False,
                    "ImportAdditionalItemAdjectives": [],
                    "ImportRestrictedAdjectives": [],
                    "ExportRequiredAdjectives": [],
                    "ExportRestrictedAdjectives": []
                },
                "ExportTokenRewardsCount": 0
            }
        }
    }


def make_bank_mail_count_response():
    return {
        "MailCount": 0
    }


def make_character_list_response():
    return {
        "success": True,
        "message": "",
        "characters": [character_to_list_entry(c) for c in saved_characters],
    }


def make_scenario_data(scenario_type="GodsReach"):
    return {
        "archived": False,
        "uuid": "00000000-0000-0000-0000-000000000100",
        "is_ek": False,
        "scenario_active": True,
        "scenario_type": scenario_type,
        "scenario_type_name": scenario_type,
        "name": f"Dev {scenario_type}",
        "description": "Local development server",
        "description_long": "",
        "primary_image_path": "",
        "secondary_image_path": "",
        "is_public": True,
        "region_name": "us-east",
        "server_endpoint": "127.0.0.1:8900",
        "state": "running",
        "running": True,
        "loading": False,
        "population_band": 0,
        "ek_current_population": 0,
        "ek_max_population": 100,
        "embargo_rules": {
            "locking": False,
            "default_import_count": 0,
            "default_export_count": 0,
            "winning_faction_export_count_override": 0,
            "losing_faction_export_count_override": 0,
            "min_character_level": 0,
            "max_character_level": 35,
            "inventory_restrictions": "",
            "export_equipped_no_cost": False,
            "import_equipped_no_cost": False,
            "max_character_entries": 0,
            "allow_character_reentry": True,
            "allow_early_export": False,
            "import_additional_item_adjectives": [],
            "import_restricted_adjectives": [],
            "export_required_adjectives": [],
            "export_restricted_adjectives": [],
            "required_races": [],
            "required_archetypes": [],
        },
        "rule_component": {
            "template_name": scenario_type,
            "rule_type": "campaign",
            "description_id": "",
            "max_pop": 100,
            "guild_cap": 0,
            "alliance_cap": 0,
            "guild_cap_percent": 0.0,
            "alliance_cap_percent": 0.0,
            "is_pve": scenario_type == "GodsReach",
            "require_faction": True,
            "player_faction_override_name": "",
            "faction_type": "three_faction",
            "allow_enemy_grouping": False,
            "allow_destruction": False,
            "player_death_loot_rule": "",
            "use_guild_as_faction": False,
            "use_group_loot": False,
            "group_size_min": 1,
            "group_size_max": 5,
            "embargo_rule": "",
            "rules": [],
        },
        "run_meter_component": {
            "type": "infinite",
            "next_refresh": "",
            "minutes_remaining": 999999,
            "refresh_amount_in_minutes": 0,
        },
        "schedule_component": {
            "infinite_duration": True,
            "start_date": "2020-01-01T00:00:00Z",
            "end_date": "2099-12-31T00:00:00Z",
            "timezone_offset": 0,
        },
        "owner_name": "",
        "last_error": "",
        "winning_faction": 0,
        "supports_rewards": False,
        "points_accumulation": False,
        "show_scoreboard": False,
        "campaign_siege_schedule": "",
        "ek_time_remaining": 0,
        "tile_icon": "",
        "alliance_rules": {},
        "entry_info": {
            "characters": [],
            "tickets_used": 0,
        },
    }



def make_character_create_response(req_body):
    """Build a response for POST /character/create.

    dump.cs CreateCharacterResponse struct has only three fields:
      bool   success
      string message
      string object_guid
    """
    char_guid = str(uuid.uuid4())
    return char_guid, {
        "success": True,
        "message": "",
        "object_guid": char_guid,
    }


def make_character_entry_from_request(req_body, char_guid):
    """Build a character list entry from the create request fields."""
    return {
        "name": req_body.get("character_name") or "NewCharacter",
        "object_guid": char_guid,
        "archetype_name": req_body.get("archetype_name", "Archetype_Ranger"),
        "race_name": req_body.get("race_name", "Race_Human"),
        "gender_id": req_body.get("gender_id", 0),
        "level": 1,
        "vessel_quality": 15,
        "customization_tints": convert_tints(req_body.get("vessel_tints", [])),
        "customization_features": convert_features(req_body.get("vessel_features", [])),
        "equipment_items": [],
        "inventory_items": [],
        "vessel_talent_allocations": [],
        "vessel_stat_allocations": [],
        "vessel_stat_rewards": [],
    }


class AuthHandler(BaseHTTPRequestHandler):


    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)


    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(length)


    def do_GET(self):
        print(f"GET {self.path}")
        self.log_request_full("GET")
        p = self.path.split('?')[0]

        if p == '/':
            self.send_json("Oh Hi Mark, Crowfell server is running")
        elif p == '/login/hello':
            self.send_json({"valid": True})

        elif p.startswith('/login/'):
            self.send_json(make_login_response())

        elif p in ('/events/', '/events'):
            self.send_json([])

        elif p == '/public/servers':
            self.send_json({
                "servers": [
                    {
                        "serverName": "DevWorld",
                        "public_address": "127.0.0.1:8900",
                        "public_ipv6_address": "",
                        "region": "us-east",
                        "allowed_scenario_types": ["EternalKingdom"]
                    }
                ]
            })

        elif p == '/character/list':
            self.send_json(make_character_list_response())

        elif p in ('/character/npe/templates', '/character/hungerdome/templates'):
            self.send_json([])

        elif p == '/guild/user/guild-membership':
            self.send_json({"GuildId": "", "RankId": ""})

        elif p == '/scenario_reward/list/unclaimed_participant_rewards':
            self.send_json({"UnclaimedRewardsByScenario": {}, "Timestamp": int(time.time())})

        elif p == '/chat/info':
            # ChatLoginInfo: userName, server, startingChannels, authorizedCommands
            # Return empty server to prevent WebSocket connection attempt
            self.send_json({
                "userName": "bearlikelion",
                "server": "",
                "startingChannels": [],
                "authorizedCommands": [],
            })

        elif p.startswith('/ek/campaigns/available/'):
            scenario_type = p.rsplit('/', 1)[-1]
            scenario = make_scenario_data(scenario_type)
            # The client deserializes this two ways:
            #   1. Bare array for the lobby scenario list display
            #   2. ScenarioListResponse { scenarios: [ScenarioEntry] } for
            #      OnGRScenarioListResponse (BeginOptimalGRSelection)
            # Return the ScenarioListResponse wrapper with ScenarioEntry fields.
            self.send_json({
                "scenarios": [
                    {
                        "ScenarioUuid": scenario["uuid"],
                        "ScenarioName": scenario["name"],
                        "ScenarioEnd": "2099-12-31T00:00:00Z",
                        "ScenarioRegion": scenario["region_name"],
                        "ScenarioType": scenario["scenario_type"],
                        "ScenarioOwner": scenario.get("owner_name", ""),
                        "ScenarioTypeName": scenario["scenario_type_name"],
                        "Capacity": 0.0,
                    }
                ],
            })

        elif p.startswith('/ek/status/'):
            # ScenarioDataResponse { ScenarioData: ScenarioData }
            self.send_json({
                "ScenarioData": make_scenario_data("GodsReach"),
            })

        elif p.startswith('/ek/campaigns/running'):
            self.send_json({"scenarios": []})

        elif p.startswith('/faction/get_faction_list/'):
            # /faction/get_faction_list/{scenario_uuid}/{max_pop}/{offset}
            # Returns List<FactionData> (CrowfallCommonUtilities.FactionData)
            def make_faction(fid, name, adjective):
                return {
                    "FactionId": fid,
                    "StaticFactionName": name,
                    "GuildId": "",
                    "PlayerCanJoin": True,
                    "ScoreboardVisible": True,
                    "DefaultRating": 1000,
                    "Allegiance": "",
                    "ParentFactionId": 0,
                    "RouteAdjective": adjective,
                    "Ratings": [],
                }
            self.send_json([
                make_faction(1, "Order",   "order"),
                make_faction(2, "Chaos",   "chaos"),
                make_faction(3, "Balance", "balance"),
            ])

        elif p.startswith('/faction/get_scenario_account_faction/'):
            self.send_json({"faction_id": 0})

        elif p.startswith('/map/scoreboard/'):
            self.send_json({})

        elif p.startswith('/scenario_reward/'):
            # Covers list/guild_rewards, list/participant_rewards,
            # time_tracking/getcampaigntime, etc.
            self.send_json({})

        elif p.startswith('/events/'):
            self.send_json([])

        else:
            print(f"  !! Unhandled GET: {self.path}")
            self.send_json({})


    def log_request_full(self, method, body=None):
        """Log full request details to console and requests.log."""
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        headers_str = "\n".join(f"    {k}: {v}" for k, v in self.headers.items())
        body_str = ""
        if body:
            body_text = body.decode(errors='replace')
            # Pretty-print JSON bodies
            try:
                parsed = json.loads(body_text)
                body_str = json.dumps(parsed, indent=2)
            except (json.JSONDecodeError, ValueError):
                body_str = body_text
        entry = (
            f"[{ts}] {method} {self.path}\n"
            f"  Headers:\n{headers_str}\n"
        )
        if body_str:
            entry += f"  Body:\n{body_str}\n"
        entry += "---\n"
        with open("requests.log", "a") as f:
            f.write(entry)


    def do_POST(self):
        body = self.read_body()
        p = self.path.split('?')[0]
        self.log_request_full("POST", body)

        # Pretty-print to console
        body_text = body.decode(errors='replace')
        try:
            parsed = json.loads(body_text)
            body_pretty = json.dumps(parsed, indent=2)
        except (json.JSONDecodeError, ValueError):
            body_pretty = body_text
        print(f"POST {p}\n{body_pretty}")

        if p == '/zone_transfer/enter_lobby':
            self.send_json(make_enter_lobby_response())

        elif p == '/bank/lobby_vault_bank_query':
            self.send_json(make_bank_response())

        elif p == '/bank/lobby_vault_check_bank_mail_query':
            self.send_json(make_bank_mail_count_response())

        elif p.startswith('/login/logout/'):
            self.send_json({"status": "ok"})

        elif p == '/character/create':
            try:
                req = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                req = {}
            char_guid, resp = make_character_create_response(req)
            saved_characters.append(make_character_entry_from_request(req, char_guid))
            save_characters()
            self.send_json(resp)

        elif p == '/zone_transfer/enter_scenario':
            active_character_guid = saved_characters[0]["object_guid"] if saved_characters else ""
            self.send_json({
                "success": True,
                "message": "",
                "queueToken": "mock_queue_token",
                "zoneRemoved": False,
                "canRecall": False,
                "inLobby": False,
                "characterGuid": active_character_guid,
                "currentScenarioUuid": "00000000-0000-0000-0000-000000000100",
                "zoneInfo": {
                    "endpoint": "127.0.0.1:8900",
                    "ipv6_endpoint": "",
                    "scene_name": "KingdomMain",
                    "context_id": 1
                },
                "queueInfo": {
                    "position": 0, "blocked": False,
                    "blockedReason": "", "blockedLimit": 0
                }
            })

        elif p == '/character/campaign/subscribe':
            # CampaignSubscribeResponse { success, message, scenario_uuid }
            try:
                req = json.loads(body_text)
            except (json.JSONDecodeError, ValueError):
                req = {}
            self.send_json({
                "success": True,
                "message": "",
                "scenario_uuid": req.get("scenario_uuid", ""),
            })

        elif p.startswith('/events/'):
            self.send_json({"status": "ok"})

        else:
            print(f"  !! Unhandled POST: {p}")
            self.send_json({})


    def log_message(self, fmt, *args):
        pass

if __name__ == '__main__':
    addr = ('127.0.0.1', 8080)
    print(f"Mock server listening on http://{addr[0]}:{addr[1]}")
    HTTPServer(addr, AuthHandler).serve_forever()

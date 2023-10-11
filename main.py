from async_tkinter_loop import async_mainloop, async_handler
from scapy.all import sniff
from tkinter import ttk
from tkinter import *
from wmi import WMI
import asyncio
import os
import time
import pythoncom
import nest_asyncio


nest_asyncio.apply()


class App(Tk):
    def __init__(self):
        super().__init__()
        self.title('ip_device_sniffer')
        self.minsize(width=300, height=150)
        self.geometry('300x150')
        self.lbl_interface = Label(self)
        self.lbl_interface.place(relx=0.1, rely=0.15)
        self.lbl_address = Label(self)
        self.lbl_address.place(relx=0.1, rely=0.4)
        self.btn_web = Button(self, text='Web-интерфейс', command=self.go_to_web, state='disabled')
        self.btn_web.place(relx=0.2, rely=0.7, width=180)
        self.bind('<Destroy>', self.on_exit)
        self.stop = False
        self.wmi = WMI()
        self.target_ip_address = None

        self.wait_network_connection()

    def go_to_web(self):
        os.system(f'start http://{self.target_ip_address}')

    def on_exit(self, event):
        self.stop = True

    def set_interface_static(self, interface, address):
        query_static_adapters = "select * from Win32_NetworkAdapterConfiguration where DHCPEnabled=0"
        if address not in [obj.IPAddress for obj in self.wmi.query(query_static_adapters) if obj.IPAddress]:
            os.system(f'netsh interface ip add address {interface} 0.0.0.0')

    def get_new_address(self, interface, address):
        target_ip_list = self.target_ip_address.split('.')
        try:
            if target_ip_list[-1] == '254':
                new_interface_address_list = target_ip_list[:-1] + [str(int(target_ip_list[-1]) - 1)]
            else:
                new_interface_address_list = target_ip_list[:-1] + [str(int(target_ip_list[-1]) + 1)]
            new_interface_address = '.'.join(new_interface_address_list)
            if new_interface_address not in address:
                os.system(f'netsh interface ip add address {interface} '
                          f'{new_interface_address} 255.255.255.0')
                time.sleep(3)
                return new_interface_address
        except ValueError:
            pass

    async def sniff_device(self, interface, address):
        while not self.stop:
            self.update()

            capture = sniff(iface=interface, count=1, filter='not ip6 and udp or arp')
            list_capture = str(capture[0]).split(' ')
            ip_src = list_capture[7] if 'ARP' in list_capture else list_capture[5].split(':')[0]

            if ip_src not in address:
                self.target_ip_address = ip_src
                self.lbl_address.config(text=f'IP-адреса устройства:    {self.target_ip_address}')
                self.btn_web.config(state='normal')
                return

    async def check_interface_for_enable(self, interface, address):
        query_dis_adapters = "select * from Win32_NetworkAdapter where NetEnabled=False"
        while interface not in [obj.NetConnectionID for obj in self.wmi.query(query_dis_adapters)]:
            await asyncio.sleep(.5)
        os.system(f'netsh interface ip delete address "{interface}" {address}')

    def get_enabled_network_adapters(self):
        query_en_adapters = "select * from Win32_NetworkAdapter where NetEnabled=True and NetConnectionStatus=2"
        query_en_adapters_conf = "select * from Win32_NetworkAdapterConfiguration where IPEnabled=1"

        return ([obj.NetConnectionID for obj in self.wmi.query(query_en_adapters)],
                [obj.IPAddress for obj in self.wmi.query(query_en_adapters_conf)])

    async def main_func(self, activated_interface, activated_interface_addr):
        interface_view = activated_interface[:23] + '...' if len(activated_interface) > 23 \
            else activated_interface

        self.lbl_interface.config(text=f'Подключено:    {interface_view}')
        self.lbl_address.config(text='Получение IP-адреса...')

        self.set_interface_static(activated_interface, activated_interface_addr)
        await self.sniff_device(activated_interface, activated_interface_addr)
        new_interface_address = self.get_new_address(activated_interface, activated_interface_addr)
        await self.check_interface_for_enable(activated_interface, new_interface_address)

    @async_handler
    async def wait_network_connection(self):
        pythoncom.CoInitialize()

        initial_interfaces, initial_addresses = self.get_enabled_network_adapters()

        while not self.stop:
            self.update()

            enable_interfaces, enable_interfaces_addresses = self.get_enabled_network_adapters()

            activated_interface = [adapter for adapter in enable_interfaces if adapter not in initial_interfaces]
            activated_interface_addr = [addr for addr in enable_interfaces_addresses if addr not in initial_addresses]

            try:
                if activated_interface and activated_interface_addr:
                    await self.main_func(activated_interface[0], activated_interface_addr[0])
                elif activated_interface or activated_interface_addr:
                    pass
                else:
                    self.lbl_interface.config(text='Ожидание подключения...')
                    self.lbl_address.config(text='')
                    self.btn_web.config(state='disabled')
                    initial_interfaces, initial_addresses = enable_interfaces, enable_interfaces_addresses

            except AttributeError:
                pass


app = App()
async_mainloop(app)

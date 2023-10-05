from async_tkinter_loop import async_mainloop, async_handler
from tkinter import ttk
from tkinter import *
from wmi import WMI
import asyncio
import os
import time
import pyshark
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
        self.conn = WMI()
        self.target_ip_address = None

        self.start_app()

    def go_to_web(self):
        os.system(f'start http://{self.target_ip_address}')

    def on_exit(self, event):
        self.stop = True

    def set_interface_static(self, interface, address):
        query_static_adapters = "select * from Win32_NetworkAdapterConfiguration where DHCPEnabled=0"
        if address not in [obj.IPAddress for obj in self.conn.query(query_static_adapters) if obj.IPAddress]:
            os.system(f'netsh interface ip add address {interface} 0.0.0.0')

    def get_new_address(self):
        target_ip_list = self.target_ip_address.split('.')
        if target_ip_list[-1] == '254':
            new_interface_address_list = target_ip_list[:-1] + [str(int(target_ip_list[-1]) - 1)]
        else:
            new_interface_address_list = target_ip_list[:-1] + [str(int(target_ip_list[-1]) + 1)]
        return '.'.join(new_interface_address_list)

    async def test(self, interface, address):
        allowed_protocols = ['TCP', 'UDP', 'IPv4']
        capture = pyshark.LiveCapture(interface=interface)
        for packet in capture.sniff_continuously():
            if packet.transport_layer in allowed_protocols and packet.ip.src not in address:
                self.target_ip_address = str(packet.ip.src)
                self.lbl_address.config(text=f'IP-адреса устройства:    {self.target_ip_address}')
                self.btn_web.config(state='normal')
                new_interface_address = get_new_address()

                if new_interface_address not in address:
                    os.system(f'netsh interface ip add address {interface} '
                              f'{new_interface_address} 255.255.255.0')
                time.sleep(3)
                return new_interface_address

    async def check_interface_for_enable(self, interface, address):
        query_dis_adapters = "select * from Win32_NetworkAdapter where NetEnabled=False"
        while interface not in [obj.NetConnectionID for obj in self.conn.query(query_dis_adapters)]:
            await asyncio.sleep(.5)
        os.system(f'netsh interface ip delete address "{interface}" {address}')

    def get_enabled_network_adapters(self):
        query_en_adapters = "select * from Win32_NetworkAdapter where NetEnabled=True and NetConnectionStatus=2"
        query_en_adapters_conf = "select * from Win32_NetworkAdapterConfiguration where IPEnabled=1"

        return ([obj.NetConnectionID for obj in self.conn.query(query_en_adapters)],
                [obj.IPAddress for obj in self.conn.query(query_en_adapters_conf)])

    @async_handler
    async def start_app(self):
        pythoncom.CoInitialize()

        initial_interfaces, initial_addresses = self.get_enabled_network_adapters()

        while not self.stop:
            self.update()

            enable_interfaces, enable_interfaces_addresses = self.get_enabled_network_adapters()

            activated_interface = [adapter for adapter in enable_interfaces if adapter not in initial_interfaces]
            activated_interface_addr = [addr for addr in enable_interfaces_addresses if addr not in initial_addresses]

            try:
                if activated_interface and activated_interface_addr:
                    interface_str = activated_interface[0][:23] + '...' if len(activated_interface[0]) > 23 \
                        else activated_interface[0]

                    self.lbl_interface.config(text=f'Подключено:    {interface_str}')
                    self.lbl_address.config(text='Получение IP-адреса...')

                    self.set_interface_static(activated_interface[0], activated_interface_addr[0])
                    new_interface_address = await self.test(activated_interface[0], activated_interface_addr[0])
                    await self.check_interface_for_enable(activated_interface[0], new_interface_address)
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


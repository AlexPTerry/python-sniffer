import io
import sys
import time
from collections import deque
from threading import Thread
from scapy.all import sniff
import keyboard
import tkinter as tk
from tkinter import scrolledtext, Listbox, END

BUFFER_TIME = 1
PACKETS_BUFFER = deque(maxlen=BUFFER_TIME * 1000)

PACKETS_DETAILS = []

def packet_callback(packet):
    """Callback for every captured packet. Store the packet in the buffer."""
    PACKETS_BUFFER.append(packet)

def continuous_capture():
    """Continuously capture packets."""
    sniff(prn=packet_callback, store=0)

def get_packet_details(packet):
    """Capture the output of packet.show() and return it as a string."""
    old_stdout = sys.stdout
    new_stdout = io.StringIO()
    sys.stdout = new_stdout
    packet.show()
    output = new_stdout.getvalue()
    sys.stdout = old_stdout
    return output

def dump_packets_to_gui(listbox, details_text):
    """Dump packets from the buffer to the GUI listbox."""
    for packet in list(PACKETS_BUFFER):
        listbox.insert(END, packet.summary())
        PACKETS_DETAILS.append(get_packet_details(packet))

def display_packet_detail(event, listbox, details_text):
    """Display detailed packet representation."""
    selected_index = listbox.curselection()[0]
    packet_detail = PACKETS_DETAILS[selected_index]
    
    details_text.config(state=tk.NORMAL)
    details_text.delete(1.0, tk.END)
    details_text.insert(tk.END, packet_detail)
    details_text.config(state=tk.DISABLED)

def gui():
    window = tk.Tk()
    window.title("Packet Capture")

    packet_list = Listbox(window, width=80, height=10)
    packet_list.pack(pady=20)
    packet_list.bind('<Double-Button-1>', lambda event: display_packet_detail(event, packet_list, details_text))

    details_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=80, height=10)
    details_text.pack(pady=20)
    details_text.config(state=tk.DISABLED)

    start_btn = tk.Button(window, text="Start Capture", command=lambda: Thread(target=continuous_capture).start())
    start_btn.pack()

    def check_hotkey():
        if keyboard.is_pressed('q'):
            dump_packets_to_gui(packet_list, details_text)
            time.sleep(2)
            dump_packets_to_gui(packet_list, details_text)
        window.after(100, check_hotkey)

    window.after(100, check_hotkey)
    window.mainloop()

if __name__ == "__main__":
    gui()

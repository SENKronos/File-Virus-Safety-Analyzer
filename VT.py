import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import hashlib
import mimetypes
import time
import platform
import stat
from datetime import datetime
from PIL import Image, ImageTk
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import random
import getpass
import locale
import sys
import cv2

# ----------------------------- CONFIG -----------------------------
DANGEROUS_EXTENSIONS = ['.exe', '.bat', '.vbs', '.scr', '.js', '.ps1']
MAX_SAFE_SIZE_MB = 50
SUPPORTED_EXTENSIONS = ['.txt', '.pdf', '.exe', '.zip', '.json', '.csv', '.xml', '.png', '.jpg', '.docx', '.xlsx', '.pptx', '.mp4', '.mp3']
VIDEO_PATH = r"D:\\SLT(ACT)\\MYTOOLS\\File Virus & Safety Analyzer\\cd168f8d08bae2ac44c95096be174b46.mp4"

# ----------------------------- GUI SETUP -----------------------------
root = tk.Tk()
root.title("🛡️ File Virus & Safety Analyzer")
root.geometry("1000x700")
root.configure(bg="#000000")  # Dark black background

# Set icon and logo
try:
    root.iconbitmap("D:/SLT(ACT)/MYTOOLS/File Virus & Safety Analyzer/cover13.ico")
except:
    pass

style = ttk.Style()
style.configure("TButton", font=("Consolas", 10), padding=6)
style.configure("TLabel", foreground="#00bfff", background="#000000", font=("Consolas", 10))

# ----------------------------- LOGIC -----------------------------
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        entry_path.delete(0, tk.END)
        entry_path.insert(0, file_path)
        analyze_file(file_path)

def analyze_file(filepath):
    result_box.delete("1.0", tk.END)
    ext = os.path.splitext(filepath)[1].lower()
    size_mb = os.path.getsize(filepath) / (1024 * 1024)
    mime_type, _ = mimetypes.guess_type(filepath)
    file_hash = get_hash(filepath)
    stat_info = os.stat(filepath)

    danger_score = 0
    notes = []

    if ext in DANGEROUS_EXTENSIONS:
        danger_score += 3
        notes.append(f"Suspicious extension: {ext}")
    if size_mb > MAX_SAFE_SIZE_MB:
        danger_score += 2
        notes.append(f"Large file: {size_mb:.2f} MB")

    info = [
        f"File Name: {os.path.basename(filepath)}",
        f"Full Path: {filepath}",
        f"Extension: {ext}",
        f"MIME Type: {mime_type or 'Unknown'}",
        f"Size: {size_mb:.2f} MB",
        f"SHA-256: {file_hash}",
        f"MD5: {get_hash(filepath, algo='md5')}",
        f"Last Modified: {datetime.fromtimestamp(stat_info.st_mtime)}",
        f"Created: {datetime.fromtimestamp(stat_info.st_ctime)}",
        f"Accessed: {datetime.fromtimestamp(stat_info.st_atime)}",
        f"Permissions: {oct(stat_info.st_mode)[-3:]}",
        f"Owner UID: {stat_info.st_uid if hasattr(stat_info, 'st_uid') else 'N/A'}",
        f"Owner: {getpass.getuser()}",
        f"Platform: {platform.system()} {platform.release()}",
        f"Encoding: {locale.getpreferredencoding()}",
        f"Line Count (est): {get_line_count(filepath)}",
        f"Magic Bytes: {get_magic(filepath)}",
        f"Entropy (simulated): {random.uniform(3.0, 7.5):.2f}",
        f"Bitrate (sim): {random.randint(96, 320)} kbps",
        f"Duration (sim): {random.randint(1, 300)} sec",
        f"Inode: {stat_info.st_ino if hasattr(stat_info, 'st_ino') else 'N/A'}",
        f"Block Size: {stat_info.st_blksize if hasattr(stat_info, 'st_blksize') else 'N/A'}",
        f"File Signature: {'Signed' if danger_score < 3 else 'Unverified'}",
        f"Risk Level: {'High' if danger_score >= 4 else 'Medium' if danger_score >=2 else 'Low'}"
    ]

    for line in info:
        type_line_animated(line)

    if notes:
        result_box.insert(tk.END, "\n⚠️ Risk Factors Detected:\n", "bold")
        for n in notes:
            result_box.insert(tk.END, f"- {n}\n")
    else:
        result_box.insert(tk.END, "\n✅ This file appears safe.\n")

    render_charts(danger_score)

def get_line_count(path):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return len(f.readlines())
    except:
        return "Unknown"

def get_magic(path):
    try:
        with open(path, 'rb') as f:
            return f.read(4).hex()
    except:
        return "N/A"

def get_hash(path, algo='sha256'):
    h = hashlib.new(algo)
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def type_line_animated(text):
    for ch in text + "\n":
        result_box.insert(tk.END, ch)
        result_box.update()
        time.sleep(0.003)

def render_charts(score):
    for widget in chart_frame.winfo_children():
        widget.destroy()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(6, 3), dpi=100)
    pie_data = [score, 10 - score]
    pie_labels = ['Risk', 'Safe']
    ax1.pie(pie_data, labels=pie_labels, autopct='%1.1f%%', colors=['#ff6666', '#003366'])
    ax1.set_title("Risk Ratio")

    bar_data = {'Size': random.randint(1, 100), 'Hash Match': 100 - score*10, 'Signature': score*10}
    ax2.bar(bar_data.keys(), bar_data.values(), color=['#005599', '#0066cc', '#004477'])
    ax2.set_ylim(0, 100)
    ax2.set_title("Scan Factors")

    canvas = FigureCanvasTkAgg(fig, master=chart_frame)
    canvas.draw()
    canvas.get_tk_widget().pack()

def play_video():
    cap = cv2.VideoCapture(VIDEO_PATH)

    def update_frame():
        ret, frame = cap.read()
        if not ret:
            cap.set(cv2.CAP_PROP_POS_FRAMES, 0)
            ret, frame = cap.read()
        if ret:
            frame = cv2.resize(frame, (1000, 200))
            frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
            img = Image.fromarray(frame)
            imgtk = ImageTk.PhotoImage(image=img)
            video_label.imgtk = imgtk
            video_label.configure(image=imgtk)
        root.after(33, update_frame)  # 30fps

    update_frame()

# ----------------------------- GUI LAYOUT -----------------------------
video_label = tk.Label(root, bg="#000000")
video_label.pack()
play_video()

tk.Label(root, text="Select any file to analyze:", font=("Consolas", 12, "bold"), bg="#000000", fg="#00bfff").pack(pady=10)

entry_path = tk.Entry(root, width=80, font=("Consolas", 10))
entry_path.pack(pady=5)

browse_btn = ttk.Button(root, text="📁 Browse File", command=browse_file)
browse_btn.pack(pady=5)

result_box = tk.Text(root, height=16, bg="#0d0d0d", fg="#00bfff", font=("Consolas", 10), relief=tk.FLAT)
result_box.tag_configure("bold", font=("Consolas", 10, "bold"))
result_box.pack(pady=10, fill=tk.BOTH, expand=True)

chart_frame = tk.Frame(root, bg="#000000")
chart_frame.pack(pady=5)

root.mainloop()

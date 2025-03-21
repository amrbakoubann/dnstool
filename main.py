import tkinter as tk
from dns_query_tool.gui import DNSQueryTool

def main():
    root = tk.Tk()
    app = DNSQueryTool(root)
    root.mainloop()

if __name__ == "__main__":
    main()

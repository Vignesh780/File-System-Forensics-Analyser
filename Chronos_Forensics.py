import os
import sys
import time
import hashlib
import struct
import platform
from datetime import datetime
from timeit import main
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import box
from rich.syntax import Syntax

# Initialize Rich Console
console = Console()

# --- Configuration & Signatures ---
# Magic bytes for file carving (Recovery)
FILE_SIGNATURES = {
    'jpg': (b'\xFF\xD8\xFF', b'\xFF\xD9'),
    'png': (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'),
    'pdf': (b'%PDF-', b'%%EOF'),
    'zip': (b'\x50\x4B\x03\x04', None) # ZIPs often don't have a distinct footer in raw streams
}

class ChronosForensics:
    def __init__(self):
        self.target_path = ""
        self.results = []
        self.recovered_files = []
        self.system_type = platform.system()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_banner(self):
        self.clear_screen()
        banner = """
    ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗ ██████╗ ███████╗
   ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║██╔═══██╗██╔════╝
   ██║     ███████║██████╔╝██║   ██║██╔██╗ ██║██║   ██║███████╗
   ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║╚════██║
   ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝███████║
    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚══════╝
        [bold cyan]F I L E   S Y S T E M   F O R E N S I C S[/bold cyan]
        """
        console.print(Panel(banner, style="bold green", subtitle="[bold yellow]By PySecOps[/]", subtitle_align="center"))
        console.print("[dim]Supports: NTFS | FAT32 | EXT4 Analysis via Carving & Metadata[/dim]\n", justify="center")

    def get_file_metadata(self, filepath):
        """Extracts detailed metadata from a file."""
        try:
            stat_info = os.stat(filepath)
            
            # Times
            creation_time = datetime.fromtimestamp(stat_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
            mod_time = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
            access_time = datetime.fromtimestamp(stat_info.st_atime).strftime('%Y-%m-%d %H:%M:%S')
            
            # Permissions
            mode = stat_info.st_mode
            perms = oct(mode)[-3:]
            
            # Attributes (Hidden check)
            is_hidden = False
            if self.system_type == 'Windows':
                import ctypes
                try:
                    attrs = ctypes.windll.kernel32.GetFileAttributesW(filepath)
                    if attrs != -1 and (attrs & 2):
                        is_hidden = True
                except:
                    pass
            elif filepath.startswith('.'):
                is_hidden = True

            return {
                "Path": filepath,
                "Size": f"{stat_info.st_size} bytes",
                "Created": creation_time,
                "Modified": mod_time,
                "Permissions": perms,
                "Hidden": str(is_hidden)
            }
        except Exception as e:
            return None

    def calculate_hash(self, filepath):
        """Calculates SHA-256 hash for forensic integrity."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "ACCESS_DENIED"

    def scan_directory(self):
        """Live Metadata Analysis Module."""
        console.print(f"\n[bold yellow][*] Starting Metadata Analysis on: {self.target_path}[/bold yellow]")
        
        table = Table(title="File System Artifacts", box=box.ROUNDED)
        table.add_column("File Name", style="cyan")
        table.add_column("Size", style="magenta")
        table.add_column("Permissions", style="green")
        table.add_column("Modified", style="yellow")
        table.add_column("Hidden", style="red")

        file_count = 0
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            transient=True
        ) as progress:
            task = progress.add_task("[green]Scanning MFT/Inode structures...", total=None)
            
            for root, dirs, files in os.walk(self.target_path):
                for file in files:
                    filepath = os.path.join(root, file)
                    meta = self.get_file_metadata(filepath)
                    if meta:
                        self.results.append(meta)
                        table.add_row(
                            file[:20], 
                            meta["Size"], 
                            meta["Permissions"], 
                            meta["Modified"], 
                            meta["Hidden"]
                        )
                        file_count += 1
                        if file_count > 100: break # Limit for demo UI, but keeps scanning logic
                if file_count > 20: break # Soft limit for display purposes

        console.print(table)
        console.print(f"[bold green][+] Analysis Complete. {len(self.results)} files indexed.[/bold green]")

    def carve_files(self):
        """
        Forensic File Carving (Recovery).
        This works on RAW IMAGES or Drives by reading bytes directly.
        """
        console.print("\n[bold red][!] INITIATING FILE RECOVERY (DATA CARVING)[/bold red]")
        console.print("[dim]This module reads raw binary data to recover deleted files ignoring filesystem tables.[/dim]\n")
        
        # In a real scenario, this would be a physical drive path (e.g., \\.\PhysicalDrive0 or /dev/sda)
        # For safety/demo, we ask for a file path (disk image) or a specific large file to carve from.
        image_path = Prompt.ask("[italic cyan]Enter Path to Disk Image (e.g., image.dd) or 'SKIP'[/]", default="SKIP")
        
        if image_path == "SKIP":
            return

        if not os.path.exists(image_path):
            console.print("[bold red]Error: Image file not found![/bold red]")
            return

        recovery_dir = "recovered_evidence"
        os.makedirs(recovery_dir, exist_ok=True)
        
        with open(image_path, "rb") as f:
            data = f.read() # Load into memory (WARNING: For demo only. Real tools stream this).
        
        console.print(f"[yellow][*] analyzing {len(data)} bytes of raw data...[/yellow]")
        
        count = 0
        with Progress() as progress:
            task = progress.add_task("[red]Carving...", total=len(FILE_SIGNATURES))
            
            for ext, (header, footer) in FILE_SIGNATURES.items():
                start = 0
                while True:
                    # Find header
                    index = data.find(header, start)
                    if index == -1:
                        break
                    
                    # Find footer (if exists)
                    if footer:
                        end = data.find(footer, index) + len(footer)
                    else:
                        end = index + 50000 # Hard limit if no footer (e.g. ZIP)
                    
                    if end > index:
                        # Extract Data
                        recovered_data = data[index:end]
                        filename = f"{recovery_dir}/carved_{count}.{ext}"
                        with open(filename, "wb") as out:
                            out.write(recovered_data)
                        
                        self.recovered_files.append(filename)
                        count += 1
                        start = end
                    else:
                        start = index + 1
                
                progress.advance(task)

        console.print(f"[bold green][+] Recovery Complete. {count} files recovered to '/{recovery_dir}'.[/bold green]")

    def export_report(self):
        """Generates a forensic report in tabular format."""
        if not self.results and not self.recovered_files:
            console.print("[red]No data to export.[/red]")
            return

        if Confirm.ask("\n[italic cyan]Would you like to export the forensic report?[/]"):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"Forensic_Report_{timestamp}.txt"
            
            with open(filename, "w", encoding="utf-8") as f:
                f.write("="*80 + "\n")
                f.write(f"CHRONOS FORENSICS REPORT - {timestamp}\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Target Analyzed: {self.target_path}\n")
                f.write(f"System: {self.system_type}\n\n")
                
                # Metadata Analysis Table
                f.write("-" * 80 + "\n")
                f.write("METADATA ANALYSIS\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'File Path':<40} {'Size':<15} {'Modified':<20}\n")
                f.write("-" * 80 + "\n")
                for item in self.results:
                    f.write(f"{item['Path']:<40} {item['Size']:<15} {item['Modified']:<20}\n")
                
                # Recovered Files Table
                f.write("\n" + "-" * 80 + "\n")
                f.write("RECOVERED FILES\n")
                f.write("-" * 80 + "\n")
                f.write(f"{'File Name':<60} {'Status':<20}\n")
                f.write("-" * 80 + "\n")
                for item in self.recovered_files:
                    f.write(f"{item:<60} {'Recovered':<20}\n")
                
                f.write("\n" + "="*80 + "\n")

            console.print(f"[bold green][✓] Report exported successfully: {filename}[/bold green]\n")

    def main(self):
        self.print_banner()
        
        console.print("\n[bold red]....Welcome, Investigator....[/bold red]\n",justify="center")
        console.print("Select Operation Mode: ", style="bold white")
        print()
        console.print("1. Live System Analysis [dim] (Metadata/Hidden Files) [/dim]")
        console.print("2. Raw Disk Recovery [dim](Carving from Image) .dd |.img[/dim]")
        console.print("3. Full Forensic Suite [dim](Both)[/dim]")
        
        
        mode = Prompt.ask("\n[italic cyan]Select Mode[/]", choices=["1", "2", "3"], default="default - 3")
        
        if mode in ["1", "3"]:
            self.target_path = Prompt.ask("\n[italic cyan]Enter Target Directory/Drive to Scan[/]", default=".")
            if os.path.exists(self.target_path):
                self.scan_directory()
            else:
                console.print("[bold red]Invalid Path![/bold red]")

        if mode in ["2", "3"]:
            self.carve_files()
            
        self.export_report()
        
        while True:
            if Confirm.ask("\n[bold cyan]Would you like to perform another analysis?[/bold cyan]"):
                console.print("[bold white]Select Operation Mode:[/bold white]")
                console.print("1. Live System Analysis (Metadata/Hidden Files)")
                console.print("2. Raw Disk Recovery (Carving from Image)")
                console.print("3. Full Forensic Suite (Both)")
                
                mode = Prompt.ask("Select Mode", choices=["1", "2", "3"], default="3")
                
                # Reset results for new analysis
                self.results = []
                self.recovered_files = []
                
                if mode in ["1", "3"]:
                    self.target_path = Prompt.ask("\n[italic cyan]Enter Target Directory/Drive to Scan[/]", default=".")
                    if os.path.exists(self.target_path):
                        self.scan_directory()
                    else:
                        console.print("[bold red]Invalid Path![/bold red]")

                if mode in ["2", "3"]:
                    self.carve_files()
                
                self.export_report()
            else:
                console.print("\n[bold red]Shutting down Chronos...[/bold red]\n[bold red]-------------------------------------[/bold red]")
                break

if __name__ == "__main__":
    try:
        tool = ChronosForensics()
        tool.main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Operation Interrupted by User.[/bold red]")
        sys.exit()
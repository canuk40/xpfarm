import sys
import argparse
import socket
import re
import ipaddress
import logging
from urllib.parse import urlparse

try:
    from rich.console import Console
    from rich.table import Table
    from rich.logging import RichHandler
    import ui
    import db
    import tool_manager
except ImportError as e:
    print(f"Error: Required packages or local modules not found: {e}")
    sys.exit(1)

# Setup Rich Console
console = Console()

def setup_logging(verbose):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, rich_tracebacks=True, markup=True)]
    )
    return logging.getLogger("xpfarm")

def parse_args():
    parser = argparse.ArgumentParser(description="xpfarm - Automated Testing CLI")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-t", "--target", help="Comma separated targets (e.g. domain.com,1.2.3.4)")
    group.add_argument("-l", "--list", help="File path containing targets")
    
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase verbosity")
    parser.add_argument("-x", "--proxy", help="Proxy URL (e.g. http://127.0.0.1:8080)")
    parser.add_argument("-cf", "--cloudflare", action="store_true", help="Allow Cloudflare targets (do not exclude them)")
    parser.add_argument("-s", "--stats", action="store_true", help="Show statistics table")
    
    return parser.parse_args()

def resolve_ip(target):
    """
    Attempt to resolve a target to an IP.
    Returns IP string if resolved, None otherwise.
    Handles:
    - IP addresses (returns as is)
    - Domains (resolves)
    - URLs (extracts hostname then resolves)
    - Wildcards (strips *. then resolves)
    """
    hostname = target
    
    # Handle URL
    if "://" in target:
        try:
            parsed = urlparse(target)
            hostname = parsed.netloc
            # Remove port if present
            if ':' in hostname:
                hostname = hostname.split(':')[0]
        except Exception:
            pass
            
    # Handle Wildcard
    if hostname.startswith("*."):
        hostname = hostname[2:]
        
    # check if it is already an IP
    try:
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        # Not an ipv4, try resolving
        pass
        
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        return None

def get_target_type(target):
    """
    Determine the type of the target.
    Categories: Web Application, Wildcard, IP, Domain
    """
    if target.startswith("http://") or target.startswith("https://"):
        return "Web Application"
    if target.startswith("*."):
        return "Wildcard"
    
    # Check if IP
    try:
        if "/" in target: # CIDR?
             ipaddress.ip_network(target)
             return "IP Range" # Or just IP
        ipaddress.ip_address(target)
        return "IP"
    except ValueError:
        pass
        
    return "Domain"

def process_targets(targets_raw, logger, allow_cf):
    valid_targets = []
    
    with ui.get_progress_bar(console, description="Validating targets...") as progress:
        task_id = progress.add_task(description="Validating targets...", total=len(targets_raw))
        
        for raw_t in targets_raw:
            progress.advance(task_id)
            t = raw_t.strip()
            if not t:
                continue
                
            logger.debug(f"Processing target: {t}")
            
            # Simple Validation (Exclude obvious junk)
            if " " in t: # Basic check if parsing failed splitting by comma
                 # actually user said "comma seperation is optional" in file, but -t is comma separated. 
                 # We split main list by comma, so t shouldn't have spaces ideally unless file line had them.
                 pass
    
            ip = resolve_ip(t)
            
            if not ip:
                logger.warning(f"[bold red]{t}[/] [bold yellow]Excluded: Could not resolve or validate[/]")
                continue
                
            # Check Cloudflare
            is_cf = db.is_cloudflare_ip(ip)
            if is_cf:
                if allow_cf:
                    logger.info(f"Target {t} ({ip}) is [yellow]Cloudflare[/], but allowed via flag.")
                else:
                    logger.warning(f"[bold red]{t}[/] ([bold red]{ip}[/]) [bold yellow]Excluded: Cloudflare IP[/]")
                    continue
            
            # Determine Type
            target_type = get_target_type(t)
            
            logger.info(f"[bold green]{t}[/] ({ip}) [[cyan]{target_type}[/]]")
            valid_targets.append((t, target_type))
        
    return valid_targets

def main():
    args = parse_args()
    logger = setup_logging(args.verbose)
    
    # Initialize DB (run the db script logic)
    logger.info("Initializing Database...")
    try:
        db.init_db()
        # We also want to ensure ranges are there. db.py main block does this, we should call the function.
        # Check if we have ranges, if not insert defaults.
        ranges = db.get_cloudflare_ranges()
        if not ranges:
            logger.info("Populating Cloudflare IP ranges...")
            count = db.insert_cloudflare_ranges(db.CLOUDFLARE_RANGES)
            logger.info(f"Inserted {count} Cloudflare ranges.")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)

    # Tool Verification
    logger.info("Verifying external tools...")
    tool_manager.verify_tools(logger)

    # Proxy Setup (Placeholder logic)
    if args.proxy:
        logger.info(f"Using Proxy: {args.proxy}")
        # Here we would configure requests/pysocks globally if needed
        # import socks
        # import socket
        # ... setup logic ...

    targets = []
    
    # Parse Targets
    if args.target:
        # User said "comma seperation is optional", but for -t usually implies it.
        # "domain.com, 127.0.0.1" -> split by comma
        raw_list = args.target.split(',')
        targets.extend(raw_list)
        
    if args.list:
        try:
            with open(args.list, 'r') as f:
                content = f.read()
                # Handle both newlines and commas in file
                # Replace newlines with commas then split
                content = content.replace('\n', ',')
                file_targets = content.split(',')
                targets.extend(file_targets)
        except FileNotFoundError:
            logger.error(f"List file not found: {args.list}")
            sys.exit(1)

    if not targets:
        logger.error("No targets found.")
        sys.exit(1)

    logger.info(f"Parsed {len(targets)} potential targets. Validating...")
    
    valid_targets = process_targets(targets, logger, args.cloudflare)
    
    # Summary
    if args.stats:
        table = Table(title="Target Summary")
        table.add_column("Total Input", style="cyan")
        table.add_column("Valid Targets", style="green")
        table.add_column("Excluded/Invalid", style="red")
        
        table.add_row(str(len(targets)), str(len(valid_targets)), str(len(targets) - len(valid_targets)))
        console.print(table)
    
    if valid_targets:
        console.print(f"\n[bold]Ready to test {len(valid_targets)} targets.[/]")
        # Placeholder for future logic where we "save future results"
    else:
        console.print("\n[bold red]No valid targets to proceed.[/]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Script interrupted by user. Exiting...[/]")
        sys.exit(0)

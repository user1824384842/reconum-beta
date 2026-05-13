import asyncio
import ipaddress
import math
import os

from models import Target, TargetType
from workers import SubdomainWorker, HttpxWorker, NmapWorker, NucleiWorker



RESULTS_FILE = "scans/session_results.jsonl"


def _write_line(line: str) -> None:
    """Blocking write — called via asyncio.to_thread to avoid blocking the loop."""
    os.makedirs("scans", exist_ok=True)
    with open(RESULTS_FILE, "a") as f:
        f.write(line + "\n")


async def log_result(target: Target) -> None:
    """FIX: offload blocking file I/O off the event loop."""
    await asyncio.to_thread(_write_line, target.model_dump_json())



def identify_input(input_str: str) -> TargetType:
    clean = input_str.strip()
    if "/" in clean:
        return TargetType.CIDR
    try:
        ipaddress.ip_address(clean)
        return TargetType.IP
    except ValueError:
        return TargetType.DOMAIN


async def resolve_dns_async(target: Target) -> bool:
    loop = asyncio.get_event_loop()
    try:
        addrinfo = await loop.getaddrinfo(target.address, None)
        for _, _, _, _, sockaddr in addrinfo:
            target.resolved_ips.add(sockaddr[0])
        return True
    except Exception as e:
        target.is_dead = True
        target.error_log.append(f"dns_resolve_failed: {e}")
        return False




async def process_target(target: Target, queue: asyncio.Queue, workers: dict) -> None:
    """Run the full recon pipeline for a single target."""

    
    if target.type == TargetType.DOMAIN and not target.parent_domain:
        subdomains = await workers["sub"].run(target)
        for sub in subdomains:
            await queue.put(sub)

    
    if target.type == TargetType.DOMAIN:
        if not await resolve_dns_async(target):
            await log_result(target)
            return


    target = await workers["nmap"].run(target)

    if target.is_dead:
        await log_result(target)
        return


    open_ports = {s.port for s in target.services}
    http_ports = {80, 443, 8080, 8443, 8888}
    if open_ports & http_ports or "http" in target.tags or "https" in target.tags:
        target = await workers["httpx"].run(target)


    target = await workers["nuclei"].run(target)

    await log_result(target)
    print(
        f"[+] {target.address:<30} "
        f"services={len(target.services)}  "
        f"vulns={len(target.vulnerabilities)}  "
        f"errors={len(target.error_log)}"
    )



async def agent(queue: asyncio.Queue, workers: dict) -> None:
    while True:
        target = await queue.get()
        try:
            await process_target(target, queue, workers)
        except Exception as e:
            target.error_log.append(f"unhandled_pipeline_error: {e}")
            await log_result(target)
            print(f"[!] Unhandled error for {target.address}: {e}")
        finally:
            queue.task_done()


async def main() -> None:
    cores = os.cpu_count() or 1
    TOTAL_SLOTS = cores * 4
    main_sem = asyncio.Semaphore(TOTAL_SLOTS)
    nmap_sem = asyncio.Semaphore(max(1, math.floor(TOTAL_SLOTS / 3)))
    nuclei_sem = asyncio.Semaphore(max(1, math.floor(TOTAL_SLOTS / 6)))

    workers = {
        "sub":    SubdomainWorker(main_sem),
        "httpx":  HttpxWorker(main_sem),
        "nmap":   NmapWorker(nmap_sem),
        "nuclei": NucleiWorker(nuclei_sem),
    }

    queue: asyncio.Queue = asyncio.Queue()

    # seed the queue - edit this list to change targets
    raw_inputs = [
        "192.168.111.132",
    ]

    for item in raw_inputs:
        item = item.strip()
        if not item:
            continue
        t_type = identify_input(item)
        if t_type == TargetType.CIDR:
            for ip in ipaddress.ip_network(item, strict=False).hosts():
                await queue.put(Target(raw_input=item, type=TargetType.IP, address=str(ip)))
        else:
            await queue.put(Target(raw_input=item, type=t_type, address=item))

    print(f"[*] Starting reconum | slots={TOTAL_SLOTS} | targets seeded={queue.qsize()}")


    tasks = [asyncio.create_task(agent(queue, workers)) for _ in range(TOTAL_SLOTS)]
    await queue.join()


    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

    print(f"[*] Done. Results written to {RESULTS_FILE}")


if __name__ == "__main__":
    asyncio.run(main())
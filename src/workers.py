import asyncio
import json
import os
import xml.etree.ElementTree as ET

from models import Target, TargetType, Service, Vulnerability


class SubdomainWorker:
    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore

    async def run(self, target: Target) -> list[Target]:
        if target.type != TargetType.DOMAIN:
            return []

        async with self.semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    "subfinder", "-d", target.address, "-silent",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    target.error_log.append(
                        f"subfinder error: {stderr.decode().strip()}"
                    )
                    return []

                results = []
                for line in stdout.decode().splitlines():
                    subdomain = line.strip()
                    if subdomain:
                        results.append(
                            Target(
                                raw_input=target.raw_input,
                                type=TargetType.DOMAIN,
                                address=subdomain,
                                parent_domain=target.address,
                            )
                        )
                return results

            except Exception as e:
                target.error_log.append(f"subfinder exception: {e}")
                return []


class NmapWorker:
    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore

    async def run(self, target: Target) -> Target:
        async with self.semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    "nmap", "-Pn",
                    "--top-ports", "1000",
                    "--min-rate", "2000",
                    "--max-retries", "1",
                    "--host-timeout", "1m",
                    "-oX", "-",
                    target.address,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    target.error_log.append(
                        f"nmap tier1 error: {stderr.decode().strip()}"
                    )
                    target.is_dead = True
                    return target

                root = ET.fromstring(stdout.decode())
                found_ports = [
                    p.get("portid")
                    for p in root.findall(".//port")
                    if p.find("state") is not None
                    and p.find("state").get("state") == "open"
                ]

                if not found_ports:
                    target.is_dead = True
                    return target

                
                p_arg = ",".join(found_ports)
                process_v = await asyncio.create_subprocess_exec(
                    "nmap", "-sV", "-Pn",
                    "--version-intensity", "5",
                    "-p", p_arg,
                    "-oX", "-",
                    target.address,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout_v, stderr_v = await process_v.communicate()

                if process_v.returncode != 0:
                    target.error_log.append(
                        f"nmap tier2 error: {stderr_v.decode().strip()}"
                    )
                    return target

                root_v = ET.fromstring(stdout_v.decode())
                for p in root_v.findall(".//port"):
                    state_node = p.find("state")
                    if state_node is None or state_node.get("state") != "open":
                        continue

                    s_node = p.find("service")
                    service_name = "unknown"
                    product = None
                    version = None
                    extrainfo = None

                    if s_node is not None:
                        service_name = s_node.get("name", "unknown")
                        product = s_node.get("product")
                        version = s_node.get("version")
                        extrainfo = s_node.get("extrainfo")

                    srv = Service(
                        port=int(p.get("portid")),
                        name=service_name,
                        product=product,
                        version=version,
                        extrainfo=extrainfo,
                    )
                    target.services.append(srv)
                    target.tags.add(srv.name)
                    target.tags.add("cve")
                    if srv.product:
                        target.tags.add(srv.product.lower())

            except ET.ParseError as e:
                target.error_log.append(f"nmap xml parse error: {e}")
            except Exception as e:
                target.error_log.append(f"nmap exception: {e}")

            return target


class HttpxWorker:
    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore

    async def run(self, target: Target) -> Target:
        async with self.semaphore:
            try:
                process = await asyncio.create_subprocess_exec(
                    "httpx",
                    "-u", target.address,
                    "-silent", "-json", "-td", "-title",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if not stdout:
                    return target

                for line in stdout.decode().splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                        for tech in data.get("technologies", []):
                            target.technologies.add(tech)
                            target.tags.add(tech.lower())
                        title = data.get("title", "N/A")
                        target.tags.add(f"title:{title}")
                    except json.JSONDecodeError as e:
                        target.error_log.append(f"httpx json parse error: {e}")

            except Exception as e:
                target.error_log.append(f"httpx exception: {e}")

            return target


class NucleiWorker:
    _templates_ready: bool = False

    def __init__(self, semaphore: asyncio.Semaphore):
        self.semaphore = semaphore

    @classmethod
    async def _ensure_templates(cls) -> bool:
        """
        Verify that nuclei-templates are present in the image.
        Templates are baked in at `docker build` time — no network calls needed at runtime.
        Returns False (with a clear error) only if the image was built with SKIP_TEMPLATES=1
        or something went wrong during the build.
        """
        if cls._templates_ready:
            return True

        templates_path = os.path.expanduser("~/nuclei-templates")

        has_templates = False
        if os.path.isdir(templates_path):
            for root, _, files in os.walk(templates_path):
                depth = root[len(templates_path):].count(os.sep)
                if depth > 3:
                    continue
                if any(f.endswith(".yaml") for f in files):
                    has_templates = True
                    break

        if has_templates:
            cls._templates_ready = True
            return True

        print(
            "[!] nuclei-templates not found — was the image built with SKIP_TEMPLATES=1?\n"
            "    Rebuild without that flag: docker compose build --no-cache"
        )
        return False

    async def run(self, target: Target) -> Target:
        scan_tags = [t for t in target.tags if ":" not in t]
        if not scan_tags or not target.services:
            return target

        
        if not await NucleiWorker._ensure_templates():
            target.error_log.append("nuclei skipped: templates unavailable")
            return target

        async with self.semaphore:
            try:
                query = ",".join(set(scan_tags))
                process = await asyncio.create_subprocess_exec(
                    "nuclei",
                    "-as",                      
                    "-tags", query,             
                    "-disable-update-check",   
                    "-silent",
                    "-jsonl",
                    "-target", target.address,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()

                if process.returncode != 0:
                    target.error_log.append(
                        f"nuclei error: {stderr.decode().strip()}"
                    )
                    return target

                if stdout:
                    for line in stdout.decode().splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            res = json.loads(line)
                            info = res.get("info", {})
                            vuln_id = res.get("template-id", "unknown")
                            vuln_name = info.get("name", "unknown")
                            vuln_severity = info.get("severity", "unknown")

                            target.vulnerabilities.append(
                                Vulnerability(
                                    id=vuln_id,
                                    name=vuln_name,
                                    severity=vuln_severity,
                                    description=info.get("description"),
                                    extracted_results=res.get("extracted-results", []),
                                )
                            )
                        except json.JSONDecodeError as e:
                            target.error_log.append(f"nuclei json parse error: {e}")

            except Exception as e:
                target.error_log.append(f"nuclei exception: {e}")

            return target
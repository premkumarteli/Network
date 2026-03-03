import asyncio
import logging
from ..db.session import get_db_connection
from .risk_engine import risk_engine

logger = logging.getLogger("netvisor.services.flow")

# Buffered queues for high-performance ingestion
flow_queue = asyncio.Queue(maxsize=10000)

class FlowService:
    async def buffer_flow(self, flow_data):
        try:
            flow_queue.put_nowait(flow_data)
            return True
        except asyncio.QueueFull:
            logger.error("Flow queue full - dropping flow")
            return False

    async def flow_writer_worker(self):
        """Async worker to persist flows and trigger detection."""
        while True:
            batch = []
            # Get first item
            item = await flow_queue.get()
            batch.append(item)
            
            # Try to get more for a batch
            while len(batch) < 100:
                try:
                    item = flow_queue.get_nowait()
                    batch.append(item)
                except asyncio.QueueEmpty:
                    break
            
            if batch:
                await self._persist_batch(batch)
                for _ in range(len(batch)):
                    flow_queue.task_done()

    async def _persist_batch(self, batch):
        conn = get_db_connection()
        if not conn: return
        try:
            cursor = conn.cursor(dictionary=True)
            for flow in batch:
                # 1. Evaluate Risk
                # Fetch baseline (Simplified for now)
                cursor.execute("SELECT * FROM device_baselines WHERE device_id = %s", (flow.src_ip,))
                baseline = cursor.fetchone()
                
                report = risk_engine.evaluate_flow(flow, baseline)
                
                # 2. Persist Flow Log
                sql = """
                    INSERT INTO flow_logs (
                        organization_id, src_ip, dst_ip, src_port, dst_port,
                        protocol, start_time, last_seen, packet_count, byte_count,
                        duration, average_packet_size, domain, agent_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(sql, (
                    flow.organization_id, flow.src_ip, flow.dst_ip, flow.src_port, flow.dst_port,
                    flow.protocol, flow.start_time, flow.last_seen, flow.packet_count, flow.byte_count,
                    flow.duration, flow.average_packet_size, flow.domain, flow.agent_id
                ))
                
                # 3. Update Device Risk
                cursor.execute("""
                    INSERT INTO device_risks (device_id, organization_id, ip_address, current_score, risk_level, reasons)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE 
                        current_score = VALUES(current_score),
                        risk_level = VALUES(risk_level),
                        reasons = VALUES(reasons)
                """, (flow.src_ip, flow.organization_id, flow.src_ip, report["score"], report["severity"], ",".join(report["reasons"])))

                # 4. Create Alert if High Risk
                if report["severity"] in ["HIGH", "CRITICAL"]:
                    import json
                    cursor.execute("""
                        INSERT INTO alerts (organization_id, device_ip, severity, risk_score, breakdown_json)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (flow.organization_id, flow.src_ip, report["severity"], report["score"], json.dumps(report["breakdown"])))

            conn.commit()
            cursor.close()
        except Exception as e:
            logger.error(f"Flow Persistence Error: {e}")
        finally:
            conn.close()

flow_service = FlowService()

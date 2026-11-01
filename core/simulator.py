from .models import NetworkBlocklist
import time
import random
import threading
from datetime import datetime

active_simulations = {}
DEVICES = ['Workstation 01', 'Laptop 02', 'Office Server', 'Mobile Device', 'Network Printer']

class SimulationSession:
    def __init__(self, user_id, scenario):
        self.user_id = user_id
        self.scenario = scenario
        self.state = 'idle'
        self.progress = 0
        self.devices = {dev: 'normal' for dev in DEVICES}
        self.events = []
        self.features = None
        self.prediction = None
        self.thread = None
        self.lock = threading.Lock()

    def start(self):
        if self.state in ['idle', 'completed']:
            self.state = 'scanning'
            self.progress = 0
            self.events = []
            self.features = None
            self.prediction = None
            self.devices = {dev: 'normal' for dev in DEVICES}
            self.thread = threading.Thread(target=self._run_scan, daemon=True)
            self.thread.start()

    def stop(self):
        self.state = 'idle'

    def reset(self):
        self.stop()
        self.progress = 0
        self.events = []
        self.features = None
        self.prediction = None
        self.devices = {dev: 'normal' for dev in DEVICES}

    def _run_scan(self):
        for i in range(50):
            if self.state != 'scanning':
                break
            with self.lock:
                self.progress = int((i + 1) / 50 * 100)
                new_events = self._generate_events()
                self.events.extend(new_events)
                self._update_device_status(new_events)
            time.sleep(0.2)

        if self.state == 'scanning':
            with self.lock:
                self.state = 'completed'
                self.features = self._extract_features(self.events)

    def _generate_events(self):
        events = []
        if self.scenario == 'normal': count = random.randint(1, 3)
        elif self.scenario in ['port_scan', 'brute_force']: count = random.randint(5, 10)
        elif self.scenario == 'dos': count = random.randint(10, 20)
        else: count = random.randint(2, 8)
        
        blocked_devices = list(NetworkBlocklist.objects.filter(is_active=True).values_list('source_device', flat=True))
        
        for _ in range(count):
            src = random.choice(DEVICES)
            is_blocked = src in blocked_devices
            dst = 'Monitoring Server' if random.random() > 0.3 else random.choice([d for d in DEVICES if d != src])
            
            event = {
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'src': src, 'dst': dst,
                'src_port': random.randint(1024, 65535),
                'dst_port': random.choice([80, 443, 22, 3389, 8080]),
                'status': 'success', 'direction': 'outbound',
                'bytes': 0, 'duration': 0
            }

            if self.scenario == 'normal':
                event['bytes'] = random.randint(500, 5000)
                event['duration'] = random.uniform(0.5, 2.0)
                event['status'] = 'success'
            elif self.scenario == 'port_scan':
                event['dst_port'] = random.randint(1, 1024)
                event['status'] = 'failed'
                event['bytes'] = random.randint(40, 100)
                event['duration'] = random.uniform(0.01, 0.1)
            elif self.scenario == 'dos':
                event['bytes'] = random.randint(10000, 50000)
                event['duration'] = random.uniform(0.01, 0.05)
                event['status'] = 'success'
            elif self.scenario == 'brute_force':
                event['dst_port'] = 22
                event['status'] = 'auth_failed'
                event['bytes'] = random.randint(200, 500)
                event['duration'] = random.uniform(0.5, 1.5)
            elif self.scenario in ['mixed', 'random']:
                sub = random.choice(['normal', 'normal', 'normal', 'port_scan', 'brute_force'])
                if sub == 'normal':
                    event['bytes'] = random.randint(500, 5000); event['duration'] = random.uniform(0.5, 2.0)
                elif sub == 'port_scan':
                    event['dst_port'] = random.randint(1, 1024); event['status'] = 'failed'; event['bytes'] = 60; event['duration'] = 0.05
                elif sub == 'brute_force':
                    event['dst_port'] = 22; event['status'] = 'auth_failed'; event['bytes'] = 300; event['duration'] = 1.0
                    
            if is_blocked:
                event['blocked'] = True
                event['status'] = 'blocked'
            else:
                event['blocked'] = False
            
            events.append(event)
        return events

    def _update_device_status(self, events):
        for e in events:
            if e['status'] in ['failed', 'auth_failed']:
                self.devices[e['src']] = 'suspicious'

    def _extract_features(self, events):
        if not events: return None
        duration = sum(e['duration'] for e in events) / len(events)
        bytes_src_dst = sum(e['bytes'] for e in events if e['direction'] == 'outbound')
        bytes_dst_src = sum(e['bytes'] for e in events if e['direction'] == 'inbound')
        failed = sum(1 for e in events if e['status'] in ['failed', 'auth_failed', 'blocked'])
        frequency = len(events) / 10.0
        anomaly = min(1.0, (failed / max(1, len(events))) * 0.7 + (frequency / 10.0) * 0.3)
        
        return {
            'duration_seconds': round(duration, 2),
            'bytes_src_to_dst': bytes_src_dst,
            'bytes_dst_to_src': bytes_dst_src,
            'failed_connections': failed,
            'connection_frequency': round(frequency, 2),
            'service_anomaly_score': round(anomaly, 2),
            'src_device': self.events[-1]['src'] if self.events else 'Unknown'
        }

    def get_state(self):
        with self.lock:
            return {
                'state': self.state, 'progress': self.progress,
                'devices': self.devices, 'events': self.events[-20:],
                'total_events': len(self.events),
                'features': self.features, 'prediction': self.prediction
            }
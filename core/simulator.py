
import time
import random
import threading
from datetime import datetime

# Store active simulators in memory
active_simulators = {}

class TrafficSimulator:
    def __init__(self, scenario, user_id):
        self.scenario = scenario
        self.user_id = user_id
        self.running = False
        self.paused = False
        self.events = []
        self.thread = None
        self.latest_features = None
        self.latest_prediction = None
        self.lock = threading.Lock()

    def start(self):
        if not self.running:
            self.running = True
            self.paused = False
            self.events = []
            self.latest_features = None
            self.latest_prediction = None
            self.thread = threading.Thread(target=self._run_loop, daemon=True)
            self.thread.start()

    def stop(self):
        self.running = False
        self.paused = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def _run_loop(self):
        while self.running:
            if not self.paused:
                with self.lock:
                    new_events = self._generate_events()
                    self.events.extend(new_events)
                    self.events = self.events[-50:] # Keep last 50 events
                    
                    self.latest_features = self._extract_features(self.events)
                    
                    if self.latest_features:
                        from core.ml import determine_detection_result
                        self.latest_prediction = determine_detection_result(self.latest_features)
            
            time.sleep(2) # Tick every 2 seconds

    def _generate_events(self):
        events = []
        count = random.randint(3, 8)
        
        for _ in range(count):
            if self.scenario == 'normal':
                events.append({'duration': random.uniform(10, 60), 'bytes_sent': random.randint(500, 5000), 'bytes_recv': random.randint(1000, 15000), 'failed': 0})
            elif self.scenario == 'port_scan':
                events.append({'duration': random.uniform(0.1, 1.0), 'bytes_sent': random.randint(40, 100), 'bytes_recv': 0, 'failed': 1})
            elif self.scenario == 'dos':
                events.append({'duration': random.uniform(0.01, 0.5), 'bytes_sent': random.randint(1000, 5000), 'bytes_recv': 0, 'failed': 0})
            elif self.scenario == 'brute_force':
                events.append({'duration': random.uniform(1, 3), 'bytes_sent': random.randint(200, 500), 'bytes_recv': random.randint(100, 300), 'failed': 1})
            elif self.scenario == 'suspicious':
                events.append({'duration': random.uniform(2, 5), 'bytes_sent': random.randint(100, 1000), 'bytes_recv': random.randint(100, 1000), 'failed': random.choice([0, 1])})
        return events

    def _extract_features(self, events):
        if not events: return None
        
        duration = sum(e['duration'] for e in events) / len(events)
        bytes_src_dst = sum(e['bytes_sent'] for e in events)
        bytes_dst_src = sum(e['bytes_recv'] for e in events)
        failed = sum(1 for e in events if e['failed'] == 1)
        frequency = len(events) / 2.0 
        anomaly = min(1.0, (failed / max(1, len(events))) * 0.7 + (frequency / 20.0) * 0.3)

        return {
            'duration_seconds': round(duration, 2),
            'bytes_src_to_dst': bytes_src_dst,
            'bytes_dst_to_src': bytes_dst_src,
            'failed_connections': failed,
            'connection_frequency': round(frequency, 2),
            'service_anomaly_score': round(anomaly, 2)
        }

    def get_status(self):
        with self.lock:
            return {
                'running': self.running,
                'paused': self.paused,
                'events_count': len(self.events),
                'features': self.latest_features,
                'prediction': self.latest_prediction
            }

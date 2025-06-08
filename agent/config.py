import os
import yaml
import json

class Config:
    def __init__(self, path="config.yaml"):
        if not os.path.exists(path):
            raise FileNotFoundError(f"Config file not found: {path}")
        with open(path, 'r') as f:
            data = yaml.safe_load(f) or {}
        # Core modules config
        self.scan = data.get('scan', {})
        self.capture = data.get('capture', {})
        self.anomaly = data.get('anomaly', {})
        # Database config
        self.database = data.get('database', {})
        # Authentication config
        self.auth = data.get('auth', {})
        # Default auth initialization
        self.auth_defaults = data.get('auth_defaults', {})
        # RBAC definitions
        self.rbac = data.get('rbac', {})

    @classmethod
    def load(cls):
        # allow YAML or JSON override via env var
        cfg_path = os.getenv('NOC_AGENT_CONFIG', 'config.yaml')
        # Support JSON if extension is .json
        if cfg_path.endswith('.json'):
            if not os.path.exists(cfg_path):
                raise FileNotFoundError(f"Config file not found: {cfg_path}")
            with open(cfg_path, 'r') as f:
                data = json.load(f)
            # Temporarily write YAML file for consistency
            temp_path = 'config_from_json.yaml'
            with open(temp_path, 'w') as yf:
                yaml.safe_dump(data, yf)
            cfg = cls(temp_path)
            os.remove(temp_path)
            return cfg
        else:
            return cls(cfg_path)
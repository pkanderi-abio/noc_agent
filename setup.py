# setup.py
from setuptools import setup, find_packages

# Read the long description from README
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='noc_agent',
    version='0.1.0',
    author='Your Name',
    author_email='support@hhitsolutions.com',
    description='Network Operations Center agent with scanning, anomaly detection, and API',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/your_org/noc_agent',
    # Automatically include the 'agent' package and subpackages
    packages=find_packages(include=['agent', 'agent.*']),
    # Include top-level scripts as modules
    py_modules=['user_management', 'train_anomaly'],
    include_package_data=True,
    install_requires=[
        'python-nmap',
        'scapy',
        'pyshark',
        'cryptography',
        'PyYAML',
        'joblib',
        'scikit-learn',
        'fastapi',
        'uvicorn',
        'pandas',
        'prometheus_client',
        'python-jose[cryptography]',
        'passlib[bcrypt]',
        'SQLAlchemy',
        'alembic',
        'pytest',
        'pytest-asyncio',
        'httpx'
    ],
    entry_points={
        'console_scripts': [
            'noc-agent=agent.agent:main',
        ],
    },
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.8',
)

"""Example Python application, using the paved path."""

try:  # for pip >= 10
    from pip._internal.req import parse_requirements
except ImportError:  # for pip <= 9.0.3
    from pip.req import parse_requirements
try:  # for pip >= 10
    from pip._internal.download import PipSession
except ImportError:  # for pip <= 9.0.3
    from pip.download import PipSession

from setuptools import setup


# Gather install requirements from requirements.txt
install_reqs = parse_requirements('requirements.txt', session=PipSession())
install_requires = [str(ir.req) for ir in install_reqs]


setup(
    name='cloudtrail_anomaly',
    versioning='build-id',
    author='Will Bengtson',
    keywords='cloudtrail',
    url='https://github.com/netflix-skunkworks/cloudtrail-anomaly',
    setup_requires=['setupmeta'],
    python_requires='>=3.6',
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'ct_anomaly = cloudtrail_anomaly.cli:cli'
        ]
    }
)

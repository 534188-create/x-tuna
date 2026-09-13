"""Чистая граница первой функциональной staging-пробы, без операций и subset PASS."""
from __future__ import annotations

from typing import Any

from .decoy_health import _vpn_targets
from .models import validate_manifest
from .naive_probes import _native_profile_shape
from .renderers import frontend_listener_inventory, frontend_material_inventory
from .vpn_probes import _simple_profile

_INVALID = 'Кандидат не прошёл проверку области staging'


def staging_eligibility_errors(manifest: dict[str, Any], *, packages_ready: bool = False,
                               routing_material: Any = None) -> tuple[str, ...]:
    """Не подтверждает installed binary, credentials, audit или реальные маршруты.

    packages_ready предоставляет вызывающий код после проверки всех пакетов.
    Неизвестный обязательный профиль запрещает весь кандидат; список manifest
    не фильтруется ради успешной проверки поддержанного подмножества.
    """
    try:
        if type(manifest) is not dict or type(packages_ready) is not bool:
            return (_INVALID,)
        validate_manifest(manifest)
        components, decoys, lucx = manifest['components'], manifest['decoys'], manifest['lucx']
        errors = []
        if (any(components.get(name) is not True for name in ('haproxy', 'nginx', 'extended_tls_split'))
                or decoys.get('enabled') is not True or decoys.get('require_full_acceptance') is not True
                or decoys.get('routing_mode') != 'extended' or not decoys.get('sites')
                or not decoys.get('extended_routes')):
            errors.append('Нужны полный extended frontend и обязательная приёмка сайтов')
        if components.get('install_packages') is not False and not packages_ready:
            errors.append('Готовность всех пакетов должна быть подтверждена до staging')
        if any(components.get(name) for name in ('sidecar', 'naive_frontend', 'trusttunnel_backend', 'tls_hook')):
            errors.append('Дополнительные frontend и службы ещё не покрыты этой staging-пробой')
        if (manifest.get('certificates', {}).get('renewal', {}).get('enabled')
                or manifest.get('cloudflare', {}).get('enabled')):
            errors.append('Renewal и Cloudflare ещё не покрыты этой staging-пробой')
        settings = lucx.get('settings_management') or {}
        if (type(settings) is not dict or lucx.get('inbound_changes')
                or any(value for key, value in settings.items()
                       if key.startswith('sync_') or key == 'allow_inbound_changes')):
            errors.append('Изменения LucX должны быть исключены из этой staging-операции')
        protocols = manifest.get('protocols')
        if type(protocols) is not list or not protocols:
            return (*errors, 'Отсутствует полный набор VPN-профилей')
        active = []
        for protocol in protocols:
            if type(protocol) is not dict:
                return (_INVALID,)
            if any(value for key, value in protocol.items() if key.startswith('sync_')):
                errors.append('Изменения endpoint должны быть исключены из этой staging-операции')
            if protocol.get('enable') is False or protocol.get('exposure') == 'none':
                continue
            active.append(protocol)
        if not active or not all((_native_profile_shape(protocol) if protocol.get('protocol') == 'naive'
                                 else _simple_profile(protocol)) for protocol in active):
            errors.append('Не все обязательные VPN-профили поддерживаются этой staging-пробой')
        targets, target_errors = _vpn_targets(manifest)
        if not targets or target_errors:
            errors.append('Полный набор VPN endpoints не подтверждён')
        # Обе inventory используют тот же verified plan, что production renderer.
        frontend_listener_inventory(manifest, routing_material=routing_material)
        frontend_material_inventory(manifest, routing_material=routing_material)
        return tuple(dict.fromkeys(errors))
    except (AttributeError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
        # Исходное значение/домены из исключения модели не публикуются.
        return (_INVALID,)

# vless-subscription

Проверенные VLESS-ключи как подписка для Happ. Ключи проверяются локально на устройстве (TCP-проверка + латентность) и автоматически публикуются в этот репозиторий.

## Подписка для Happ

Добавь в Happ ссылку:

```
https://raw.githubusercontent.com/FobiaLabs/vless-subscription/main/subscription.txt
```

Формат — base64 от списка `vless://` ключей (стандартный формат подписок). Также доступен сырой список: `working_keys.txt`.

## Как работает

`check_and_publish.py`:
1. Загружает свежие ключи из [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia)
2. Проверяет каждый сервер с этого устройства (TCP connect, до 30 потоков, отсечка 2500 мс)
3. Сортирует по латентности, пишет `subscription.txt`, `working_keys.txt`, `stats.json`
4. Коммитит и пушит в main

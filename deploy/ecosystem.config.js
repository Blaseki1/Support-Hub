// PM2 alternative to systemd:  pm2 start deploy/ecosystem.config.js && pm2 save && pm2 startup
module.exports = { apps: [{ name: 'support-hub', script: 'server/index.js', cwd: '/opt/support-hub', instances: 1, autorestart: true, max_memory_restart: '400M', env: { NODE_ENV: 'production' } }] };

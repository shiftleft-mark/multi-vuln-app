const Koa = require('koa');
const app = new Koa();
const Router = require('@koa/router');

const router = new Router();

const execa = require('execa');

router.get('/kcmd', (ctx, next) => {
  let cmd = ctx.params.cmd;
  execa.sync(cmd, []).stdout.pipe(res);
});

router.get('/r', (ctx, next) => {
  let url = ctx.params.redirect_url;
  router.redirect(url);
});

app
  .use(router.routes())
  .use(router.allowedMethods());

app.listen(3000);

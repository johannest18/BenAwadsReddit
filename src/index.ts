import { MikroORM } from "@mikro-orm/core"
import { __prod__ } from "./constants";
// import { Post } from "./entities/Post";
import 'reflect-metadata';
import microConfig from './mikro-orm.config'
import express from 'express';
import {ApolloServer} from 'apollo-server-express';
import {buildSchema} from 'type-graphql';
import { HelloResolver } from "./resolvers/hello";
import { PostResolver } from "./resolvers/post";
import { UserResolver } from "./resolvers/user";
import redis from 'redis';
import session from 'express-session';
import connectRedis from 'connect-redis'
import { MyContext } from "./types";

const main = async () =>  {
    const orm = await MikroORM.init(microConfig);
    await orm.getMigrator().up();
    const app = express();

    const RedisStore = connectRedis(session);
    const redisClient = redis.createClient();


    app.use(
    session({
        name: 'qid',
        //Ekki disable-a ttl og touch í alvörunni
        store: new RedisStore({ client: redisClient, disableTouch: true, disableTTL: true }),
        cookie: {
            maxAge: 1000 * 60 * 60* 24 * 30,
            httpOnly: true, //bara hægt að nálgast cookie í gegnum http,
            sameSite: 'lax', //csrf
            secure: __prod__ //lætur bara virka í https
        },
        saveUninitialized: false,
        secret: 'kasdfjljhsdfjhaghuuoiuiowuerjskl',
        resave: false,
    })
    )

    const apolloServer = new ApolloServer({
        schema: await buildSchema({
            resolvers: [HelloResolver, PostResolver, UserResolver],
            validate: false
        }),
        context: ({req, res}): MyContext => ({em: orm.em, req, res})
    })


    apolloServer.applyMiddleware({app});

    app.listen(4000, () => {
        console.log('server started on localhost:4000')
    })
}

main().catch((err) => {
    console.error(err);
});
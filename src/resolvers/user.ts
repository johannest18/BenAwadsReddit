import { User } from "../entities/User";
import { MyContext } from "src/types";
import argon2 from 'argon2';
import { Arg, Ctx, Field, InputType, Mutation, ObjectType, Resolver } from "type-graphql";

@InputType()
class UsernamePasswordInput {
    @Field()
    username: string
    @Field()
    password: string
}

@ObjectType()
class FieldError {
    @Field()
    field: string;
    @Field()
    message: string;

}

@ObjectType()
class UserResponse { 
    @Field(() => [FieldError], {nullable: true})
    errors?: FieldError[]

    @Field(() => User, {nullable: true})
    user?: User
}

@Resolver()
export class UserResolver {
    @Mutation(() => UserResponse)
    async register(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() {em}: MyContext
    ): Promise<UserResponse>{
        if (options.username.length <= 2) {
            return {
                errors: [{
                    field: "username",
                    message: "to short"
                }]
            }
        }
        if (options.password.length <= 3) {
            return {
                errors: [{
                    field: "password",
                    message: "must be more than 4 of length"
                }]
            }
        }
        const hashedPassword = await argon2.hash(options.password);
        const user = em.create(User, {username: options.username, password: hashedPassword});
        try {
        await em.persistAndFlush(user);
        }
        catch(err){
            if(err.code === '23505'){
                return {errors: [{
                    field: "username",
                    message: "username already exists"
                }]}
            }
            console.log("message: ", err);
        }
        return {user};
    }

    @Mutation(() => UserResponse)
    async login(
        @Arg('options', () => UsernamePasswordInput) options: UsernamePasswordInput,
        @Ctx() {em}: MyContext
    ): Promise<UserResponse>{
        const user = await em.findOne(User, {username: options.username});
        if (!user){
            return{
                errors: [{field: 'username',
                            message: "that usename doesnt exist"}]
            };
        }
        const valid = await argon2.verify(user.password, options.password);
        if (!valid){
            return{
                errors: [{field: 'password',
                            message: "incorrect password"}]
            };
        }
        return {user};
    }
}
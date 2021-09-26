import bcrypt from 'bcryptjs'
import jwt, { JwtPayload } from 'jsonwebtoken'
import { ApolloServer, gql } from 'apollo-server'
import { MongoClient, ObjectId } from 'mongodb'
import { MongoDataSource } from 'apollo-datasource-mongodb'

const ttl = 60

function jwtSign(userId: ObjectId) {
    return jwt.sign({ userId }, 'secret', { expiresIn: '1h' })
}

class Users extends MongoDataSource<UserDocument, UserContext> {
    async login(password: string, username: string) {
        const user = await this.collection.findOne({ username })
        if (!user) throw new Error('wrong username')
        const valid = await bcrypt.compare(password, user.password)
        if (!valid) throw new Error('wrong password')
        const token = jwtSign(user._id)
        return {
            token,
            user
        }
    }
    async signup(password: string, username: string) {
        password = await bcrypt.hash(password, 10)
        const user = await this.collection.insertOne({ username, password })
        const token = jwtSign(user.insertedId)
        return {
            token,
            user: {
                _id: user.insertedId,
                username
            }
        }
    }
    currentUser() {
        return this.findOneById(this.context.userId, { ttl })
    }
}

interface UserContext {
    userId: ObjectId
}

interface UserDocument {
    dataSources: {
        users: Users
    }
}

const resolvers = {
    Mutation: {
        login: (_: void, { password, username }: { password: string, username: string }, { dataSources: { users } }: UserDocument) => {
            return users.login(password, username)
        },
        signup: (_: void, { password, username }: { password: string, username: string }, { dataSources: { users } }: UserDocument) => {
            return users.signup(password, username)
        }
    },
    Query: {
        currentUser: (_: void, __: void, { dataSources: { users } }: UserDocument) => {
            return users.currentUser()
        }
    }
}

const typeDefs = gql`
    type AuthPayload {
        token: String
        user: User
    }
    type Mutation {
        login(password: String!, username: String!): AuthPayload
        signup(password: String!, username: String!): AuthPayload
    }
    type Query {
        currentUser: User
    }
    type User {
        _id: ID
        username: String
    }
`

const { dbName = 'toucan', uri = 'mongodb://localhost:27017' } = process.env
const client = new MongoClient(uri)

await client.connect()
const db = client.db(dbName)

function getUserId(token: string) {
    return jwt.verify(token, 'secret') as JwtPayload
}

const server = new ApolloServer({
    context: ({ req }) => {
        const token = req.headers.authorization
        if (token) return getUserId(token)
    },
    dataSources: () => ({
        users: new Users(db.collection('users'))
    }),
    resolvers,
    typeDefs
})

server.listen()

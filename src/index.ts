import csrf from 'csurf';
import { Router } from 'express';
import { type NextFunction, type Request, type Response, RequestHandler } from 'express-serve-static-core';
import type { Multer } from 'multer';
import { z, type ZodObject } from 'zod';

const csrfProtection = csrf({ cookie: true });

type RouterMethods = 'get' | 'post' | 'put' | 'delete';

type PathSegment = `/${string}`;
type ValidationSchema<Shape extends Record<string, any> = Record<string, any>> = ZodObject<Shape>;

type HasKey<Shape, Key> = Key extends keyof Shape ? true : false;
export type ExtractParamsShape<Schema extends ValidationSchema = ValidationSchema> = Schema extends { ['params']: infer Params } ? Params : never;
export type ExtractQueryShape<Schema extends ValidationSchema = ValidationSchema> = Schema extends { ['query']: infer Query } ? Query : never;
export type ExtractBodyShape<Shape extends Record<string, any>> =
  HasKey<Shape, 'params'> extends true
    ? HasKey<Shape, 'body'> extends true
      ? Shape['body']
      : never
    : HasKey<Shape, 'query'> extends true
      ? HasKey<Shape, 'body'> extends true
        ? Shape['body']
        : never
      : HasKey<Shape, 'body'> extends true
    ? Shape['body']
    : Shape;

type MagikRequest<Shape extends Record<string, any>> = keyof Shape extends 'body' | 'query' | 'params'
  ? Omit<Request, keyof Shape | 'user'> & { [Key in keyof Shape]: Shape[Key] } & { user: any } // Express.User
  : Omit<Request, 'body' | 'user'> & { body: Shape, user: any }; // Express.User

type RouteFn<Data extends Record<string, any> = Record<string, any>, ReturnType = unknown> = (req: MagikRequest<Data>, res: Response, next?: NextFunction) => Promise<ReturnType> | ReturnType;

type MagikRouteFn<
  Schema extends ValidationSchema = ValidationSchema,
> = (req: MagikRequest<z.infer<Schema>>, res: Response, next?: NextFunction) => Promise<void | Response> | void | Response;

function createSchema<T extends ValidationSchema>(schema: T) {
  type SchemaType = z.infer<T>;
  return { schema, type: null as unknown as SchemaType };
}

// eslint-disable-next-line @typescript-eslint/ban-types
type OwnKeys<T> = Exclude<keyof T, keyof Object | 'prototype'>;

/**
 * Represents the metadata for a route in the MagikRouter.
 *
 * @template Schema - The validation schema for the route.
 * @template AuthorizationMethods - The authorization methods for the route.
 * @template UploadMethods - The upload methods for the route.
 * 
 * @example
 * // Defining a route with validation and authorization
 * const route: RouteMetadata = {
 *  validationSchema: userSchema,
 *  route: (req, res) => res.json(req.user),
 *  auth: 'ensureUser',
 * };
 */
type RouteMetadata<
  Schema extends ValidationSchema = ValidationSchema,
  AuthorizationMethods extends Record<string, RouteFn> = Record<string, RouteFn>,
  UploadMethods extends Record<string, Multer> = Record<string, Multer>,
> = {
  validationSchema: Schema,
  route: MagikRouteFn<Schema>
  auth?: OwnKeys<AuthorizationMethods>,
  upload?: {
    field: string,
    multer: OwnKeys<UploadMethods>,
    multi?: boolean
  }
}

/**
 * The `MagikRouter`, a mystical conduit for the digital realm.
 * 
 * @example
 * // Creating a new MagikRouter with a specific prefix and methods
 * const router = new MagikRouter('/api', authMethods, uploadMethods);
 * 
 * @example
 * // Defining a GET route with validation and authorization
 * router.get('/users', {
 *   validationSchema: userSchema,
 *   route: (req, res) => res.json(req.user),
 *   auth: 'ensureUser',
 * });
 * 
 * @example
 * // Defining a POST route with file upload
 * router.post('/upload', {
 *   validationSchema: uploadSchema,
 *   route: (req, res) => res.json({ message: 'Upload successful' }),
 *   upload: { field: 'file', multer: 'uploadMiddleware', multi: false },
 * });
 */
export class MagikRouter<Prefix extends string = string> {
  private _router: Router;

  public routePrefix: Prefix;
  public csrf = csrf({ cookie: true });

  private uploadMethods: Record<string, Multer> = {};
  private authorizationMethods: Record<string, RouteFn> = {};

  constructor(prefix: Prefix, authMethods: Record<string, RouteFn>, uploadMethods: Record<string, Multer>) {
    this.routePrefix = prefix;
    this.authorizationMethods = authMethods;
    this.uploadMethods = uploadMethods;
    this._router = Router();
  }

  ensureAuthorization<RouteData extends Record<string, any>>(ensureAuthenticatedAs: keyof MagikRouter['authorizationMethods']) {  
    return this.authorizationMethods[ensureAuthenticatedAs] as unknown as RouteFn<RouteData, Response>;
  }

  /**
   * Creates a route with the specified configuration.
   *
   * @template Schema - The validation schema type.
   * @template Method - The router method type.
   * @template Path - The path segment type.
   *
   * @param {Object} options - The options for creating the route.
   * @param {Path} options.path - The path segment for the route.
   * @param {Method} [options.method='get'] - The HTTP method for the route.
   * @param {ValidationSchema} options.validationSchema - The validation schema for the route.
   * @param {Function} options.route - The route handler function.
   * @param {boolean} [options.auth] - Indicates if authorization is required for the route.
   * @param {boolean} [options.upload] - Indicates if file upload is enabled for the route.
   *
   * @returns {Router} The router instance.
   */
  protected createRoute<
    Schema extends ValidationSchema,
    Method extends RouterMethods = RouterMethods,
    Path extends PathSegment = PathSegment,
  >({ method = 'get' as Method, validationSchema, route, auth, path, upload }: { path: Path, method: Method } & RouteMetadata<Schema, MagikRouter['authorizationMethods'], MagikRouter['uploadMethods']>): Router {
    const { schema } = createSchema(validationSchema);
    const routerArgs = [path, csrfProtection] as [Path, ...Array<RequestHandler>]

    const handler = async (req: MagikRequest<z.infer<Schema>>, res: Response) => {
      const hasReqKeys = (validationSchema.keyof().options as Array<string>).some((key) => {
        switch (key) {
          case 'body': return true
          case 'query': return true
          case 'params': return true
          default: return false;
        }
      });
      const parsedRequest = hasReqKeys ? schema.safeParse(req) : schema.safeParse(req.body);

      if (parsedRequest.success === false) {
        return res.status(400).json({ error: 'Invalid request body', details: parsedRequest.error });
      }

      const parseRequest = hasReqKeys ? { ...req, ...parsedRequest.data } : { ...req, body: parsedRequest.data };

      return route(parseRequest, res);
    }

    if (auth) routerArgs.push(this.ensureAuthorization<Schema>(auth) as unknown as RequestHandler);
    if (upload) {
      if (upload.multi) {
        routerArgs.push(this.uploadMethods[upload.multer].array(upload.field) as unknown as RequestHandler);
      } else {
        routerArgs.push(this.uploadMethods[upload.multer].single(upload.field) as unknown as RequestHandler);
      }
    }

    routerArgs.push(handler as unknown as RequestHandler);

    return this._router[method](...routerArgs);
  }

  public get router() {
    return this._router; 
  }

  /** Defines a GET route with the specified configuration */
  public get<
    Path extends PathSegment = PathSegment,
    Schema extends ValidationSchema = ValidationSchema
  >(path: Path, { validationSchema, route, auth, upload }: RouteMetadata<Schema>): void {
    this.createRoute({ path, method: 'get', validationSchema, route, auth, upload });
  }

  /** Defines a POST route with the specified configuration */
  public post<
    Path extends PathSegment = PathSegment,
    Schema extends ValidationSchema = ValidationSchema
  >(path: Path, { validationSchema, route, auth, upload }: RouteMetadata<Schema>) {
    this.createRoute({ path, method: 'post', validationSchema, route, auth, upload });
  }

  /** Defines a PUT route with the specified configuration */
  public put<
    Path extends PathSegment = PathSegment,
    Schema extends ValidationSchema = ValidationSchema
  >(path: Path, { validationSchema, route, auth, upload }: RouteMetadata<Schema>) {
    this.createRoute({ path, method: 'put', validationSchema, route, auth, upload });
  }

  /** Defines a DELETE route with the specified configuration */
  public delete<
    Path extends PathSegment = PathSegment,
    Schema extends ValidationSchema = ValidationSchema
  >(path: Path, { validationSchema, route, auth, upload }: RouteMetadata<Schema>) {
    this.createRoute({ path, method: 'delete', validationSchema, route, auth, upload });
  }
}

/* eslint-disable @typescript-eslint/no-unsafe-return */
import {
  ConfigurableModuleBuilder,
  DynamicModule,
  Global,
  Module,
  Provider,
} from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { TypeOrmModule } from '@nestjs/typeorm';
import { McpAuthJwtGuard } from './guards/jwt-auth.guard';
import { createMcpOAuthController } from './mcp-oauth.controller';
import {
  OAuthUserModuleOptions as AuthUserModuleOptions,
  OAuthEndpointConfiguration,
  OAuthModuleDefaults,
  OAuthModuleOptions,
} from './providers/oauth-provider.interface';
import { ClientService } from './services/client.service';
import { JwtTokenService } from './services/jwt-token.service';
import { OAuthStrategyService } from './services/oauth-strategy.service';
import { MemoryStore } from './stores/memory-store.service';
import {
  AuthorizationCodeEntity,
  OAuthClientEntity,
  OAuthSessionEntity,
  OAuthUserProfileEntity,
} from './stores/typeorm/entities';
import { TypeOrmStore } from './stores/typeorm/typeorm-store.service';
import { normalizeEndpoint } from '../mcp/utils/normalize-endpoint';
import { OAUTH_TYPEORM_CONNECTION_NAME } from './stores/typeorm/constants';
import { ModuleRef } from '@nestjs/core';

// Default configuration values
export const DEFAULT_OPTIONS: OAuthModuleDefaults = {
  serverUrl: 'https://localhost:3000',
  resource: 'https://localhost:3000/mcp',
  jwtIssuer: 'https://localhost:3000',
  jwtAudience: 'mcp-client',
  jwtAccessTokenExpiresIn: '60s',
  jwtRefreshTokenExpiresIn: '30d',
  cookieMaxAge: 24 * 60 * 60 * 1000, // 24 hours
  oauthSessionExpiresIn: 10 * 60 * 1000, // 10 minutes
  authCodeExpiresIn: 10 * 60 * 1000, // 10 minutes
  nodeEnv: 'development',
  apiPrefix: '',
  endpoints: {
    wellKnownAuthorizationServerMetadata:
      '/.well-known/oauth-authorization-server',
    wellKnownProtectedResourceMetadata: '/.well-known/oauth-protected-resource',
    register: '/register',
    authorize: '/authorize',
    callback: '/callback',
    token: '/token',
    revoke: '/revoke',
  },
  disableEndpoints: {
    wellKnownAuthorizationServerMetadata: false,
    wellKnownProtectedResourceMetadata: false,
  },
  protectedResourceMetadata: {
    scopesSupported: ['offline_access'],
    bearerMethodsSupported: ['header'],
    mcpVersionsSupported: ['2025-06-18'],
  },
  authorizationServerMetadata: {
    responseTypesSupported: ['code'],
    responseModesSupported: ['query'],
    grantTypesSupported: ['authorization_code', 'refresh_token'],
    tokenEndpointAuthMethodsSupported: [
      'client_secret_basic',
      'client_secret_post',
      'none',
    ],
    scopesSupported: ['offline_access'],
    codeChallengeMethodsSupported: ['plain', 'S256'],
  },
};

export const {
  ConfigurableModuleClass,
  MODULE_OPTIONS_TOKEN,
  ASYNC_OPTIONS_TYPE,
  OPTIONS_TYPE,
} = new ConfigurableModuleBuilder<AuthUserModuleOptions>()
  .setClassMethodName('forRoot')
  .setExtras<{ providers?: Provider[] }>(
    { providers: [] },
    (definition, extras) => ({
      ...definition,
      providers: [...(definition.providers || []), ...(extras.providers || [])],
    }),
  )
  .build();

/**
 * Example usage with custom injectable store:
 *
 * @Injectable()
 * export class CustomOAuthStore implements IOAuthStore {
 *   constructor(private prisma: PrismaService) {}
 *   // ... implement IOAuthStore methods
 * }
 *
 * @Module({
 *   imports: [
 *     McpAuthModule.forRootAsync({
 *       imports: [PrismaModule], // Import modules that provide dependencies
 *       providers: [CustomOAuthStore], // Register your custom store as a provider
 *       useFactory: async (configService: ConfigService, store: CustomOAuthStore) => ({
 *         // ... other options
 *         storeConfiguration: {
 *           type: 'custom',
 *           store: store, // Pass the injected instance
 *         },
 *       }),
 *       inject: [ConfigService, CustomOAuthStore],
 *     }),
 *   ],
 *   // ...
 * })
 * export class AppModule {}
 *
 * Or with a class reference (auto-resolved):
 *
 * storeConfiguration: {
 *   type: 'custom',
 *   store: CustomOAuthStore, // Pass the class, will be resolved via DI
 * }
 *
 * Or with a simple instance (no DI):
 *
 * storeConfiguration: {
 *   type: 'custom',
 *   store: new SimpleStore(), // Pass an instance directly
 * }
 */

@Global()
@Module({})
export class McpAuthModule extends ConfigurableModuleClass {
  static forRoot(options: typeof OPTIONS_TYPE): DynamicModule {
    const resolvedOptions = this.mergeAndValidateOptions(
      DEFAULT_OPTIONS,
      options,
    );

    return {
      imports: this.createImports(resolvedOptions),
      providers: this.createProviders(resolvedOptions),
      controllers: [this.createController(resolvedOptions)],
      exports: [
        JwtTokenService,
        'IOAuthStore',
        MemoryStore,
        McpAuthJwtGuard,
        OAuthStrategyService,
      ],
      ...super.forRoot(options),
    };
  }

  static forRootAsync(options: typeof ASYNC_OPTIONS_TYPE): DynamicModule {
    const baseModule = super.forRootAsync(options);

    // Create a provider for resolved options that also provides OAUTH_MODULE_OPTIONS
    const resolvedOptionsProvider: Provider = {
      provide: 'OAUTH_MODULE_OPTIONS',
      useFactory: (moduleOptions: AuthUserModuleOptions) => {
        const mergedOptions = this.mergeAndValidateOptions(
          DEFAULT_OPTIONS,
          moduleOptions,
        );
        // Prepare endpoints within the resolved options
        mergedOptions.endpoints = prepareEndpoints(
          mergedOptions.apiPrefix,
          DEFAULT_OPTIONS.endpoints,
          mergedOptions.endpoints || {},
        );
        return mergedOptions;
      },
      inject: [MODULE_OPTIONS_TOKEN],
    };

    // Create store provider based on async configuration
    const asyncStoreProvider: Provider = {
      provide: 'IOAuthStore',
      useFactory: (
        resolvedOptions: OAuthModuleOptions,
        moduleRef: ModuleRef,
      ) => {
        const storeConfig = resolvedOptions.storeConfiguration;

        if (!storeConfig || storeConfig.type === 'memory') {
          return new MemoryStore();
        }

        if (storeConfig.type === 'typeorm') {
          try {
            return moduleRef.get(TypeOrmStore, { strict: false });
          } catch {
            throw new Error(
              'TypeOrmStore is not available but typeorm store configuration was provided',
            );
          }
        }

        if (storeConfig.type === 'custom') {
          // Check if it's a class constructor or an instance
          if (typeof storeConfig.store === 'function') {
            // It's a class, try to get it from the module
            try {
              return moduleRef.get(storeConfig.store, { strict: false });
            } catch {
              // If not found, instantiate it
              return moduleRef.create(storeConfig.store);
            }
          } else {
            // It's an instance, use it directly
            return storeConfig.store;
          }
        }

        throw new Error(
          `Unknown store configuration type: ${(storeConfig as any).type}`,
        );
      },
      inject: ['OAUTH_MODULE_OPTIONS', ModuleRef],
    };

    // Create additional providers that depend on resolved options
    const additionalProviders: Provider[] = [
      resolvedOptionsProvider,
      asyncStoreProvider,
      {
        provide: MemoryStore,
        useExisting: 'IOAuthStore',
      },
      OAuthStrategyService,
      ClientService,
      JwtTokenService,
      McpAuthJwtGuard,
    ];

    // Dynamic imports array
    const dynamicImports: any[] = [
      ConfigModule,
      PassportModule.register({
        defaultStrategy: 'jwt',
        session: false,
      }),
      // JWT Module with async configuration
      JwtModule.registerAsync({
        useFactory: (resolvedOptions: OAuthModuleOptions) => ({
          secret: resolvedOptions.jwtSecret,
          signOptions: {
            issuer: resolvedOptions.jwtIssuer,
            audience: resolvedOptions.jwtAudience,
          },
        }),
        inject: ['OAUTH_MODULE_OPTIONS'],
      }),
    ];

    // Create the controller class with default endpoints
    // The actual endpoints will be overridden via the injected options
    const OAuthControllerClass = createMcpOAuthController(
      DEFAULT_OPTIONS.endpoints,
      {
        disableWellKnownAuthorizationServerMetadata: false,
        disableWellKnownProtectedResourceMetadata: false,
      },
    );

    // TypeORM configuration needs special handling
    // Only add TypeORM if we might need it
    const needsTypeOrm =
      options.useFactory || options.useExisting || options.useClass;

    if (needsTypeOrm) {
      // Add TypeORM provider
      additionalProviders.push({
        provide: TypeOrmStore,
        useClass: TypeOrmStore,
      });

      // Add TypeORM module configuration
      dynamicImports.push(
        TypeOrmModule.forRootAsync({
          name: OAUTH_TYPEORM_CONNECTION_NAME,
          useFactory: (resolvedOptions: OAuthModuleOptions) => {
            const storeConfig = resolvedOptions.storeConfiguration;
            if (storeConfig && storeConfig.type === 'typeorm') {
              return {
                ...storeConfig.options,
                name: OAUTH_TYPEORM_CONNECTION_NAME,
                entities: [
                  OAuthClientEntity,
                  AuthorizationCodeEntity,
                  OAuthSessionEntity,
                  OAuthUserProfileEntity,
                ],
              };
            }
            // Return minimal config if not using TypeORM to prevent connection errors
            return {
              type: 'sqlite',
              database: ':memory:',
              name: OAUTH_TYPEORM_CONNECTION_NAME,
              entities: [],
              synchronize: false,
              logging: false,
            };
          },
          inject: ['OAUTH_MODULE_OPTIONS'],
        }),
        TypeOrmModule.forFeature(
          [
            OAuthClientEntity,
            AuthorizationCodeEntity,
            OAuthSessionEntity,
            OAuthUserProfileEntity,
          ],
          OAUTH_TYPEORM_CONNECTION_NAME,
        ),
      );
    }

    return {
      ...baseModule,
      imports: dynamicImports,
      providers: [...(baseModule.providers || []), ...additionalProviders],
      controllers: [OAuthControllerClass],
      exports: [
        JwtTokenService,
        'IOAuthStore',
        MemoryStore,
        McpAuthJwtGuard,
        OAuthStrategyService,
        'OAUTH_MODULE_OPTIONS',
      ],
    };
  }

  private static createImports(
    options: OAuthModuleOptions,
  ): Array<DynamicModule | typeof ConfigModule> {
    // Determine imports based on configuration
    const imports = [
      ConfigModule,
      PassportModule.register({
        defaultStrategy: 'jwt',
        session: false,
      }),
      JwtModule.register({
        secret: options.jwtSecret,
        signOptions: {
          issuer: options.jwtIssuer,
          audience: options.jwtAudience,
        },
      }),
    ];

    // Add TypeORM configuration if using TypeORM store
    const storeConfig = options.storeConfiguration;
    if (storeConfig && storeConfig.type === 'typeorm') {
      const typeormOptions = storeConfig.options;
      imports.push(
        TypeOrmModule.forRoot({
          ...typeormOptions,
          // Use a unique connection name for the OAuth store to avoid clashes
          name: OAUTH_TYPEORM_CONNECTION_NAME,
          entities: [
            OAuthClientEntity,
            AuthorizationCodeEntity,
            OAuthSessionEntity,
            OAuthUserProfileEntity,
          ],
        }),
        TypeOrmModule.forFeature(
          [
            OAuthClientEntity,
            AuthorizationCodeEntity,
            OAuthSessionEntity,
            OAuthUserProfileEntity,
          ],
          OAUTH_TYPEORM_CONNECTION_NAME,
        ),
      );
    }

    return imports;
  }

  private static createProviders(options: OAuthModuleOptions): Provider[] {
    const storeConfig = options.storeConfiguration;
    const isTypeOrmStore = storeConfig?.type === 'typeorm';

    const oauthModuleOptions = {
      provide: 'OAUTH_MODULE_OPTIONS',
      useValue: options,
    };

    // Create store provider based on configuration
    const oauthStoreProvider = this.createStoreProvider(
      options.storeConfiguration,
    );

    // Create alias for compatibility with injection
    const oauthStoreAliasProvider = {
      provide: MemoryStore,
      useExisting: 'IOAuthStore',
    };

    const providers: Provider[] = [
      oauthModuleOptions,
      oauthStoreProvider,
      oauthStoreAliasProvider,
      OAuthStrategyService,
      ClientService,
      JwtTokenService,
      McpAuthJwtGuard,
    ];

    // Add TypeOrmStore to providers if using TypeORM
    if (isTypeOrmStore) {
      providers.push(TypeOrmStore);
    }

    return providers;
  }

  private static createController(options: OAuthModuleOptions) {
    options.endpoints = prepareEndpoints(
      options.apiPrefix,
      DEFAULT_OPTIONS.endpoints,
      options.endpoints || {},
    );

    // Create controller with apiPrefix
    const OAuthControllerClass = createMcpOAuthController(options.endpoints, {
      disableWellKnownAuthorizationServerMetadata:
        options.disableEndpoints.wellKnownAuthorizationServerMetadata ?? false,
      disableWellKnownProtectedResourceMetadata:
        options.disableEndpoints.wellKnownProtectedResourceMetadata ?? false,
    });

    return OAuthControllerClass;
  }

  private static mergeAndValidateOptions(
    defaults: OAuthModuleDefaults,
    options: AuthUserModuleOptions,
  ): OAuthModuleOptions {
    // Validate required options first
    this.validateRequiredOptions(options);

    // Merge with defaults
    const resolvedOptions: OAuthModuleOptions = {
      ...defaults,
      ...options,
      // Ensure jwtIssuer defaults to serverUrl if not provided
      jwtIssuer:
        options.jwtIssuer || options.serverUrl || DEFAULT_OPTIONS.jwtIssuer,
      cookieSecure:
        options.cookieSecure || process.env.NODE_ENV === 'production',
      // Merge protectedResourceMetadata with defaults
      protectedResourceMetadata: {
        ...defaults.protectedResourceMetadata,
        ...options.protectedResourceMetadata,
      },
      // Merge authorizationServerMetadata with defaults
      authorizationServerMetadata: {
        ...defaults.authorizationServerMetadata,
        ...options.authorizationServerMetadata,
      },
      // Merge disableEndpoints with defaults
      disableEndpoints: {
        ...defaults.disableEndpoints,
        ...(options.disableEndpoints || {}),
      },
    };

    // Final validation of resolved options
    this.validateResolvedOptions(resolvedOptions);

    return resolvedOptions;
  }

  private static validateRequiredOptions(options: AuthUserModuleOptions): void {
    const requiredFields: (keyof AuthUserModuleOptions)[] = [
      'provider',
      'clientId',
      'clientSecret',
      'jwtSecret',
    ];

    for (const field of requiredFields) {
      if (!options[field]) {
        throw new Error(
          `OAuthModuleOptions: ${String(field)} is required and must be provided by the user`,
        );
      }
    }
  }

  private static validateResolvedOptions(options: OAuthModuleOptions): void {
    // Validate JWT secret is strong enough
    if (options.jwtSecret.length < 32) {
      throw new Error(
        'OAuthModuleOptions: jwtSecret must be at least 32 characters long',
      );
    }

    // Validate URLs are proper format
    try {
      new URL(options.serverUrl);
      new URL(options.jwtIssuer);
    } catch {
      throw new Error(
        'OAuthModuleOptions: serverUrl and jwtIssuer must be valid URLs',
      );
    }

    // Validate provider configuration
    if (!options.provider.name || !options.provider.strategy) {
      throw new Error(
        'OAuthModuleOptions: provider must have name and strategy',
      );
    }
  }

  private static createStoreProvider(
    storeConfiguration: OAuthModuleOptions['storeConfiguration'],
  ) {
    if (!storeConfiguration || storeConfiguration.type === 'memory') {
      // Default memory store
      return {
        provide: 'IOAuthStore',
        useValue: new MemoryStore(),
      };
    }

    if (storeConfiguration.type === 'typeorm') {
      // TypeORM store
      return {
        provide: 'IOAuthStore',
        useClass: TypeOrmStore,
      };
    }

    if (storeConfiguration.type === 'custom') {
      // Custom store
      return {
        provide: 'IOAuthStore',
        useValue: storeConfiguration.store,
      };
    }

    throw new Error(
      `Unknown store configuration type: ${(storeConfiguration as any).type}`,
    );
  }
}

function prepareEndpoints(
  apiPrefix: string,
  defaultEndpoints: OAuthEndpointConfiguration,
  configuredEndpoints: OAuthEndpointConfiguration,
) {
  const updatedDefaultEndpoints = {
    wellKnownAuthorizationServerMetadata:
      defaultEndpoints.wellKnownAuthorizationServerMetadata,
    wellKnownProtectedResourceMetadata:
      defaultEndpoints.wellKnownProtectedResourceMetadata,
    callback: normalizeEndpoint(`/${apiPrefix}/${defaultEndpoints.callback}`),
    token: normalizeEndpoint(`/${apiPrefix}/${defaultEndpoints.token}`),
    revoke: normalizeEndpoint(`/${apiPrefix}/${defaultEndpoints.revoke}`),
    authorize: normalizeEndpoint(`/${apiPrefix}/${defaultEndpoints.authorize}`),
    register: normalizeEndpoint(`/${apiPrefix}/${defaultEndpoints.register}`),
  } as OAuthEndpointConfiguration;

  return {
    ...updatedDefaultEndpoints,
    ...configuredEndpoints,
  };
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (!value) {
    return fallback;
  }

  return value.trim().toLowerCase() === 'true';
}

export const swaggerConfig = () => ({
  swagger: {
    enabled: parseBoolean(process.env.SWAGGER_ENABLED, true),
    title: 'CYRP API',
    description: 'CYRP Platform API documentation',
    version: '0.1.0',
    path: 'api/docs',
  },
});

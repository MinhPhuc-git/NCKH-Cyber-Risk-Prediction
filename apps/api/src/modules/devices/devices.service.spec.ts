import { DevicesService } from './devices.service';

describe('DevicesService', () => {
  const devicesRepository = {
    createEnrollmentCode: jest.fn(),
    findManyByUserId: jest.fn(),
  };

  let service: DevicesService;

  beforeEach(() => {
    jest.clearAllMocks();

    service = new DevicesService(
      devicesRepository as never,
    );
  });

  it('creates a hashed one-time enrollment code', async () => {
    devicesRepository.createEnrollmentCode
      .mockResolvedValue(undefined);

    const result =
      await service.createEnrollmentCode(
        'user-id',
      );

    expect(result.code).toMatch(
      /^CYRP-[A-Z2-9]{4}-[A-Z2-9]{4}$/,
    );

    expect(result.expiresAt).toBeInstanceOf(
      Date,
    );

    expect(
      devicesRepository.createEnrollmentCode,
    ).toHaveBeenCalledWith(
      'user-id',
      expect.stringMatching(
        /^[a-f0-9]{64}$/,
      ),
      expect.any(Date),
    );

    expect(
      devicesRepository.createEnrollmentCode
        .mock.calls[0][1],
    ).not.toBe(result.code);
  });

  it('lists only devices owned by the current user', async () => {
    devicesRepository.findManyByUserId
      .mockResolvedValue([]);

    await service.listMyDevices('user-id');

    expect(
      devicesRepository.findManyByUserId,
    ).toHaveBeenCalledWith('user-id');
  });
});

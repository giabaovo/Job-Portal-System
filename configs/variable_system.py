ADMIN = 'ADMIN'
EMPLOYER = 'EMPLOYER'
JOB_SEEKER = 'JOB_SEEKER'

AVATAR_DEFAULT = {
    "AVATAR": "https://res.cloudinary.com/dtnpj540t/image/upload/v1680687265/my-job/images_default/avt_default.jpg",
    "COMPANY_LOGO": "https://res.cloudinary.com/dtnpj540t/image/upload/v1682831706/my-job/images_default/company_image_default.png",
    "COMPANY_COVER_IMAGE": "https://res.cloudinary.com/dtnpj540t/image/upload/v1683615297/my-job/images_default/company_cover_image_default.jpg",
}

ROLE_CHOICES = (
    (ADMIN, 'Admin'),
    (EMPLOYER, 'Employer'),
    (JOB_SEEKER, 'Job Seeker')
)

COMPANY_INFO = {
    "DARK_LOGO_LINK": "https://res.cloudinary.com/dtnpj540t/image/upload/v1681050602/my-job/my-company-media/myjob-dark-logo.png",
    "LIGHT_LOGO_LINK": "https://res.cloudinary.com/dtnpj540t/image/upload/v1681050660/my-job/my-company-media/myjob-light-logo.png",
    "EMAIL": "myjob.contact00000@gmail.com",
    "PHONE": "0888-425-094",
    "ADDRESS": "1242 QL1A, Tân Tạo A, Bình Tân, TP. Hồ Chí Minh",
    "MY_COMPANY_NAME": "CatJob"
}

DATE_TIME_FORMAT = {
    "dmY": "%d/%m/%Y",
    "Ymd": "%Y-%m-%d",
    "ISO8601": "%Y-%m-%dT%H:%M:%S.%fZ"
}
#include <stdio.h>
#include <Windows.h>
#include <WinCrypt.h>
#include <stdio.h>
#include <io.h>
#include <locale.h>

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#include "defines.h"

#define ESD_IMAGE_VERSION 0xe00UL
#define ESD_IMAGE_FLAGS ( FLAG_HEADER_COMPRESSION | FLAG_HEADER_RP_FIX | FLAG_HEADER_COMPRESS_LZMS )

#define VERSION L"20190628"

const WCHAR *known_base64_crypto_keys[] = {
    //14901
    L"BwIAAACkAABSU0EyAAQAAAEAAQCBK154a48ca1NUi4rwPvAb25g7qltZ0xm5HYKYLYA7AWrSEsmGduL1lgbH0GB0hLVp3qK3U6XBpudvCLTkcozadaKisCLDvCuAboPRgpkBjQ0g9jqU1bECrRgESQo+zypLSBtgL1vVsgHncefceZjxirjM6IeYV1Vul2St0BOcvDFQqnFLfFwehCUUs1GUQhNVOJeYUVGkEQxpvMCrO6jWzOvvFiieN6zB0ygCCsnLsk2Ns4JXe4SnsmgGf7tw+f5RjKBv7Hk3wyblOm0vzPnh6K77KhAiOcvO30cxEMHyK/kYOj8I1vHndjlqhvyD3e8qplpjQUVXe0DKYx1NTF69UdRqRv7gLwfvmE6hmJaTbe+N0DoC8Ie27WYBUiZfJSypbL282a9Vu4lNplTox6dfzf5hdE1KLiDptpCm+5rGTeEIQNIjYj7Ju0lmdDg5YobuCduao2ZsxVhrSfg0mBcsUa69uSL2mLtorZDoSS0ZEyoGudDapHiT7zd+HBQiUZaE1H90V/Zfjmmt/sbpXd+kDWs2+cRjCVRvSpqD8OSvSVO2ECR0QzLF4LpssF5G5exCs+ABvH5UMgu74rAGHPbqgSURURvxltzrVIFe1JZcv4YZwsGgi7JaKMdzF5EsLKhiLmqU0++tA5gKNFC4TwuUCP7X5eFDv7FTKWf3fmtKTE05sakAuAgTm1IPBZ5B5UtWctUwfLknsj4JlO4WQMd+sBg/NaQP9jRberZFyg0RRTXxJVRx+aBDaJdh66hF/gU=",

    //14393
    L"BwIAAACkAABSU0EyAAQAAAEAAQDpBHbDTC1rTdcSHhp58n1fBY4EaGo6ez4RYAu/RGiICloh3lm4vXz6SgEAXdQEtv0HzXXpORvkm+uWzmfl02yXDSYEvmDVw9kIn0u9pxdQiwo18ezHK55zbQV+KzisSJz97ZO9Z65i+EsoUdi7clqHDcJKEuudF0BDWt16XBTdntVBt7OMhYv549C1wRjASLIJVmWmeXz1d6fw03TWQoWNUud/UY3YGEzGcPPEnJT/Rhpp2OcXYYcKbsLwVyRK7tbF7MALxBrqU440kXjBGStcfTPYYwXg/C42RSdtZcjwYl1bbzcckpB3lkunMG741JK4MR238Dl+Md6EOt1HKji9gS7cQl5RPPv/oKCcWL6PkViWHhzvwexLM1cpLcXAAum7gPYegT2PrHZUav8yEtuGTPUi4+cHHaiXStujvZ79jXV9HeJ0NEfAcie8d+4Ctph34Skj9arHA649yhat+q6iqmNWE0uTyfPNZ9tr42hLQwITCBe+jEdOYNqSRdutNDI7dGS2uG6k7UQUSLbvZ5fHI/YULMtoVI+I/kESboMj+r+ENBDslckFxS4ubUsjJcLci1ig8kZg909tlWX+wQeuAbQCzuWJbhXPJf2IcZ2o7kfPfbmYFObPVG1FgAfEo+nKSl8Pqw/7hf6t8BzWdquWvgCuqoWMJdRqL3N5Utrm6NdS0B5sJOGqqxhEXI6O02pfO/Kmt5a+JtAA7Gv5WzYtmcdNIZX5mXqqzsCoN5Vjv6jU/q3qDsRQkXw4YbypJSQ=",

    //14390
    L"BwIAAACkAABSU0EyAAQAAAEAAQCdf7DpxvHkW+g0CYgrqi+lFMwdIx1QFes0QyeQO91Cp1KjNp1ELtVgLLw5+5qRf+yOFg+TyMewBe99drjK7pTkdEHwkswcRw9JljHk7BjyXDHpckLWmGfOFtDK0TftIUAmc6AN0HhHpugBR0tkWrNfGtW61lSKsiMWhDEVUqnkwJNQQSjBpK6rbA/7yFrFR9D6vDwg46iRmbqhwMCVzr3Wea/3lN87v6gaz+cDAEvS9mHsEEoSRVzh1EX5UMfFMuMPfYekCnagT5jhZfOlU3MLSuA5lsUOy10wErlMSUW09Pl8iDGLAp8iZQw+VGd/39KTMlm88FGrd47GxPA7l1jZz+bozGWpWaWPQQ2YqKtS3UWhg8YUaeWuJC0KGmtA7lH5F80fMNzfJStUNnUzUrLInxNg97EA4FFM45DTAIBijHvDOsMJG0K4yg3ntKHiMgyrLVpy0WfIm4KR5eoF38uIoV2fUr0Mi2EC7VYKsqEnZr3dLI4zAy+ggAJQCfbTAqy2/ecYel4egZ0odA80uSRo6gG4TbqWj4DHu/fbJrjcdXos9z45jlOsaOy6ayTmymxhIXb+oOKN25ETUItRLrsBrTDIj/ZJGSmQa4KrtarZhORX3JKuVkLjxEDdix/48o+vBttPLYPiEv0bYSpMv4R5QGcZegcqPkK48++QPrxnNkv6nZfPzZBbTEj1ZvWQSVOSNi0aIYnt8oaMvUv3jJk+NAEhyOkOOnMJXcrq6ChxlA5Hoy48zR7LLQ2S5guzXwU=",

    //14388
    L"BwIAAACkAABSU0EyAAQAAAEAAQDdv7jU8mT9zjOtXkxHf8JMsCtPfb5CBnLyLbq6fcppME4x3Cy+rs8bhs4aYmuRsopmTDt6Qc3x6tZTX+rhTZzjhgF21D0EqwCzTsyaSxI4jC5BavPzT/HXgwb843poeQ3twKEZc93PDDExxrLz+FXemK74uey9w0SvPo0yTcNhnP+I8p9p12eVCRMcN/ma2etIE2U3vVmYlsYVQlqi9bZ8Bj2F2YBpQdTz+1JzKsE7lWnmMQzig2I1+mg3Tmu4+dcj+8Kne94habjxEcDGK0L1raHcDbtkgoRi45XLF46QoFvrjd0F5CjmFYuTvyKlzLfXtLgPqDTH5R6MQU3Fz1y5lblZ26yovcceD3D63SBaUkwDrlv+1NoG+qHVFSuuiFmNFMxAExPKUeLHRa2Xt5zle8fXFOMpOpAjFZItyfG8EhtL3HukFgZnmOw6qqLzkzXI+zW6xEWIi2akaBfwLvDBM6GEk2FahaQSuTXphvcBnQ9jUR5Tf318NQqkBjiF/xKCzNV9gwi5Wuap5F5BgDjiBnxw8DUqh3NthT01IGckbA63AAWhkt0KlR1bYjmNkwvCQ3biRrxSDF7HbBP79Lx8ZardLy0EgZYhEp4yXeOdb/DLxc+mWdUqERkQ7f1Qu6+asKMQz7wKL6sZ/PszlHdluhQ0TPXNb6poAqmgVviD1br/ItIkwht7fqaNueOb4CE4fAchmvCZ4M78gUodfMV5B3Hg0//6kU/V5D6w+P0LYszkwX5xFMut1xZDUocjigE=",

    //14385
    L"BwIAAACkAABSU0EyAAQAAAEAAQDrhu20TkgPM2EU2vFdgi9LSa91FUNyNHLvu+H+IonWKFB5B7oO8YA8eZAdlIOjTLYzyDZp+GB0ojkw1cIG/OL3diJd7KURelimikpiWX4XRzybavo/qLIORAsh4nVNmXa/UG2GqP6WQKyK5hSXeZ429ebyhV3MPUN38KmvlaAP14ONHbgj2uNnUs5SR19s9Bz7DmfNhuSXeiokS01SW7S4WzPM6TuJ/IBo52MIQK4tzPFI+3c2b5LjXfFWpadMo/x5jIZRKjxeIwqQ8c67CI3AtQHDryJfVrhoIAbUdG0/6xVbIa9aQ5YHAtsFOnyH0Cv4Lo0Fwe7kSwNGqd8aT+zZA3hB22g6tJk/Zc5UxwtmFO2giIm0HlP52gnuDXq9Ga7LJg4zudAT3vnt6CaDV31k5NlVhdbHg9zEQQVsxlAvBXFRb38DX+rPNmGYFZtXDKVJI+fAFGPDt63eMJlu1NMEmfUeJHyE+TK11nnqvcmYFL1vBtoxmqm2GhulTLfP6WxrPZ9kYABl495kEYLqFD16rwbZO5hx+2UwRw1aPfaLtxOlyYayYxK7C87jUMErS30P/U6UQTBUMW8PKP9zOGl+mYmUX2RoOf1v9EpgiuGCtrzYFMQHTA0I/QgwmUadBNfZYRVTkPYEaxHgQ9ixRCQVwGQ/KmMndtj9nBHYrmaK56CghHRKAh9NXERXNxPFMx5a+Rip3eSI0LDvp3JjHnRviJJLTDn9zZGowWL7wvQeg6I8jbQzrjFhbjRTpwN0/z8=",

    //14383
    L"BwIAAACkAABSU0EyAAQAAAEAAQCtdSEzxQsEBSjVdKDS33zXhXaXePAOEPEKxkXl64uiEKa9nG0l6cDtujVs09o/8wYnc+KYJvadTW7r3sNZ3gh+vEUl1GGnjOXsMbcRAT2/U9H2rGjZ0oOwGpF81JPISPO5YulQcIoQf6vwUoOr9EDJ2fUn7ThaLkRu/5HQcbyWtO0Zk2MlolYtKLKYvZ555P0tq0qm1P26brrBIz7QWUKCcGn1tDbeu6+hltAYrVdKLtq1KMQsY8Arm5mRjrLtcuLBUgFt/4deCvD2mqSGJcZPiqOiZ08UAqX1CfoR+E8VSzoddEVQ4i4nGJEUehlCr2DN3OswfNqFV2ln379hvSfMPdfuRhB3u56rilY9l6c34Ehinm0aqHtE8s8SvwRNQx/J5AxuN2E5ueY4demqAQ4k+P0nkwlDTl+nXtcqna5NMcEfUR5I5lQo3geQVu3m4Amz9D2xyUQs1ClN5LRb/hjqPsqoi15W4chV+QvBVvMucGtdg5GdGzJD4qNOEW5xDYpT1lNsTv/8/2rcKToSjU5eOatmvqy/8s2L6D8033gEo15Ut1+a8yT1yjU/1nut9tdWypLaot0ri50Cq805yq24AYilnD1jn/tGI99/qaOLHlaO3w1JZ7TrDm6R5MCZCoT8bW6Suy7xqdxkp4YZZkemsW7DJ315XAeGeAeUWXBA9PkWIqeVH0jScyGI47RiwBVIOlwhPPPmHOmd/sTSz5WSUogdwFJ4eBOpXv2inO9qxdgxSOCquTyFO2HEPw4z8xM=",

    //14379
    L"BwIAAACkAABSU0EyAAQAAAEAAQA9RnTQ9aM4KjDBYP7Xk5He4ujJJSnEdIdy3W02ywrJQYlQGUZho7rN5N1lQBEebYJjjQDgTAdcEs/Wyp2Hrp/yyj58UNyMnRi0+V2Ni/Q+wKHJgPVJrOqKgFcTXi20MamnGab+1p0KkRDv36j4gvVZ4VhWYhEiki2wyIf6uHrvtWEb4VaenI60i8LaveafSsQ7fzUAlPSuz36CDAo1Mt4IZKT/tSFL2qqHug5wi4DF5gWktHcdV8UIe4kYIfFBV+Nd1KFeno04XdOfXpmIkSpx/ZqL66DC3GHifW7Mbr4zEMDvOmnIHCuEdP8+ptwhtl5jO/XS1FxfFRYUiHlJ5t7MocRH8mGMHDUTtmG1Ji2f0oZVS3lBVg4m0RwqhcrPIWzqSOfIlJiknJvcurtyR53x4wj/R01zWoqLYKyKrhRri7m+y6xqceDkxUX4Zetkll8hedQJBNt4AF35CPXn91ekoaDWm0hVR0RKmYT8YFV88sqXsOpAuFsrCXPQ+lKlOkW+e7Nv8GwtmkgL884Lz8B7DXLe9IZ81ckkW8zySbA7ImwKf6C0H3hf1xbnW3Kdo7Y1zznQbrr3QuCOl77u7H80ARadvvjHGfTcgx3VKoi5h1pBkMAATV/HiF2LfXQv/5cOc6DyQkUXrtUFQriobdnSUzPQjk70zo/a300wbZlnrkMkd1F+ffKpMitEcx0IUPAe59OJ+HJT6HS/Mv64iTyFuZRoYztu5Xkm7AgEblMNOeH94KGotaT6QJJkMsriYQM=",

    //14376
    L"BwIAAACkAABSU0EyAAQAAAEAAQCz/H5OwXZw9WCCmg5maHa4W6sw5O6dG8IBJEOlQ3RZRayZAEd2fOHv2a105Q2EDkaQEnrWNfVFR9vgKClf2eGhtbhVNX8ew6oFeVzO7FHWAee2t1IW9nESetNXzjfkyqgli7M9nk5ZfH9GZQlvRK4AvCwx04WXIlgK5hvLA1UT4Nks2uD9FjifWV+0n+larUeaE1ALwyHtuJ/2JqPeFEaUaYJ+pLdZ64SrN9E3BytWHzInn7qXQxtdqzZf2NkWvf9rbrHihviHHbTucloeGpVUFtd2YxTQakRZPZ1gxLmyxdbNsodrkgZQpdgalU4Ch0d2oau57o/vtgnH53Fl9U3gmSrkSiNwvYACWS0hvSrhtxbE6Jc81m1DBT25r6oNAJ35vwyH4W9p9Nr5AAGJ7GzwRYIPQ3hdydn6YmiJC4CaNo9QCPc1g+FjlXgL3NyepMBnrDcNM5SDjvjF/mDKuNdOhc+PnXtseRI2c6iddfQdAwLynRuFyIhtqJl3p4v0pKzjIMxgRrRpQeq6MnvbJCnG/ldMZs6/5HAWXUDrCL5Bg8jTwaTWYRKSxD4BBo9lxVWeQyRkdrj1C4apX6CVab5/YY+pxj7sxMGvMpdQjGVTt++WBo53Yl09G/+DMkM2wUWwHYH3rnwOxOAvaAAGuy0O1IEp14sc4artmJtiDsa9TO8KDE0MKIuw8YceuUh4FLkvs6cW9KtmGY0crq92czffU7ykora+FnRQbRPPvoCQR8N8+zrP35sg0NSlpmXlARY=",

    //14372
    L"BwIAAACkAABSU0EyAAQAAAEAAQD5FLY+u0lCnsF4u8jCNhKqVKNxOOdZ/dpZ62Q29P8NkM5dnf3ZkPxUB4Buq3gMm2z6ZRDtHt0sagJnnyNtZCQ4TMGMPTbpgbUIS4pombTc2o+5eWR3xiSQL3qo/A/Kl+CFLtXnGSxbES4FUiEB42v4YWXhaJdQaV5Iu5bMOG+PqMWMRxvuAyQRmmhCiWwUMzmbzXOmA46edTQuVZtO2BG3lYWllVWIhi6iNc/bE+ziJPnWRPe32GuxgcUWYWe1vNmlkhDDGvGfHx5O9P7Z5i2aiG9XaKoQJSoTlMcSjmUHlFlOUS7HG9iHvBwe8rcM2yfYFf+JzhX767iuz28Aay7GdXpb3p4uKzJGXTdozHXCjMAx5wmCRxA8zlpQjyWiQiv+3qzb5t1WPG9g5CcrtlP7J0O4v2CdAJiiQKlDivzyUDFo17oZnabq9CielU5ZhP8PJOk3li1xUr8VfNSwb1fZ9Se4C5Q1/2n7eB/JR/f5r+FdT+DhLJrUx0Ww13nGF2e4Q9bYQ9amZKmyrGgWS2zoI9cx9eYj0i0wDw2g0Wk2uuhLTaF/BcjFUfgUIrzJORlrSIYoqfuUto4y7Ux9+j2vjaVGwci7P6/P36suJv0Hsf4Qs9Fj5bVPOUckb08II3j1axfqhhGrJzZLGupYOYkrnT/++bz4ZHbRm5XuWbXsmqicoUO7jz++ocf5OFwmLNm3L3rLH4q9FvdupzGULU/Fv0p1v74Av31LYy/ktdMotByoeM1hRUBrXC60RTPdvyI=",

    //14371
    L"BwIAAACkAABSU0EyAAQAAAEAAQDnwsaFhU3Gr7pwehh+U8CXlxz2nDnIqrOloxwTjnbm6uwhmLThcLv9km0/RFoTA4iniBswNR+tLjjEg9EyupGWrW5uTLzB7LoVVg4AOnaFWiM77lxQqiD2Npf82YlUvgGwYw5Fd1lJG6DO/8Ct5kRrEUc6LL58MWL84rKiwdI16A8ZMPOtRqTeJESGVsqvcm2KBHOrBEhcrHnOTsTSdREuO1TCJ/rW931V0sGEQ2fDmM+ZpK/P6U6UIvATrz1Ly/ypSGYIKBiDLGpSVQTsl5Ae37ZnVIlkkJnSSUt/z4n+3sLyKWWj8Oc8GONbIVWUhrvqfVyu/2puhgoOr4P4syfrreDRlxH9b3QS0yZO34seNlsZAXcqgRO7kLlMZYJq3C1VMhWSMVDeV0mvZwF99E6B+PqiUY9ctvehfHmGs4X2xcEDd42/qz1Kc+RfWIFsdZNFWr2WTrW0Sbu9qMdrtWVxojD/FWjgqiYx2mW/4fSEhBWXedVNpKUntf2kSItJ9ijgXRh0TUF7OWXdezTe0HTqyz6j2OFUqh5/fYj4R5DGLxYwKTKfJvvY8WHybSRxW1J+E2fYrGJH7Uxt26Q9fPbliWne9NJSh93+wb4g2dO7Qdb8s3LPLGjg+Ux6UA9hvZ8lRraQRn7KxW+sud2rFZeFtR3LiZRCNygz22Ua4EgVI/Db8CcAML6MGzoOEp7Ap4mGPuq/bbeR4AGD52D3qGwHHss3AHm2qRkfqBByKYCnk5j98IYmlrGPrWCM77TrDgg=",

    //14367
    L"BwIAAACkAABSU0EyAAQAAAEAAQAb0w7FuYkeohGBNQqEe7cREziKQ8bQiLe/cUOdIefU1E86osTYAMZgSvR1rTrR4LrxQ39XvAPrak09X9wcSvd83C0Vym6NY4eaqi6bYJ5fQAdRWHWLTlIO3PwvWLuF5pKFcWv4VMqCqsHqXaTF/jUcx+A4WLTcnyIuimr8vsqi4TdqoHAp6tbGBqWTQ3Fjh5SDOQm28qDu7WpfYXcZdbXUR2E/RIsM67AIjml0LB9IXnY6uHCZuK8h45hd4FUrdfA9nMQEMg6hDVuPRywhY3BU0Albds9S3kH1D5pjwmT/chhO6cd6jzulwke96FS0Vus1LkwCDnwprHD1SjQ1XjjwUdY4jVnsb2sVGMAhO0FtYKtZqArz2Aae2KgJdq7y6gY5pI6dRRW7wyZaXerW3pcthINGUOP1Vfa519hHVOaq7C3bWXCVW9gYv8gle8F9uXJvLP20zh5GNrEukCXpLTcQuMEpTy3plUFfN2RydY7sgvol3iFQ6/jgIvEPTeKzasdv57wuJMBpXZaEwF9TOv4S+yR3/2nKnt0WjhKeuSYpD6jRABQnhfheM4j6Ukti8gUYlkMsemZ36jNCzojJdnGhzShHy8jvJ39qsrtSf7Bk12M1GK2NDv5R8M+hlnMx+HYgxmar0B+4cRd4yQH7w/b+Kvec4Lvm2nQVZCesasNozuNVoVIcNNV0VJ9jopPrLfDyvjQiaGMzLRSJdmo+yqW6lX5zT/+rxgpj1n+TvvjSoBywVxaVvVEs8oSpjoFJOAg=",

    //14366
    L"BwIAAACkAABSU0EyAAQAAAEAAQB17Oi93XlK7zqPJwymTgXfb6X4oVNMAM2P6XM2mfQmClKQRtHANJrPjm5VG+G6tam1gEoHJQ8uias3HRqYSjdEPONPNwGowRGHkJ4+C71/pUU+2QUPBEed6t6rmkZHQbfa6PJKfs4mRpqSIasPfyLDHCFx/DA57A4Zyhlgv9Mk1NlCihoxWiB/DGb0EERt52MkgeVCyw72EcKoMSqf+WXPmj1zwZ08g9c3NBTThOEPBfARZzS/PsOWYS/sZoXDxO39PCrEqa7YtYE/GP7tMp4d5j2O6q/z8gwAc9KUuu4LcJEqhPktaGJLnMvS/2tX4HeojTGiZrQts3tyk6AgEWnk6b/0TC8F4kIbJe/RnZiLMVTteyKyaDs6dTDAMzHcMp4GTRnxFnvKZNKIu6ptk/0CEHafCDyC3Tk/2uDMOgX0oylbm8g1t9UTxFoaeqo5AHvPHL1SPtw+j4A8XWfmQKFazfwVh7wEXGFLmEZgX8avtP1aex4hHKqNqZwGIpqD8KuSv27uwciB5t3qH1nks2hwSMkazx2wOPBhioUR1/AXMDr3FMWRettJE+A5JezjxI3MpIVp6kEOtPQpzmOw+ZY7KQzZxH4NqEA18Rvakvo8F6+DfEX12tKyvvmm4Mp5JoFNQqN3z/Y/Ck7VnJrCSHSr9kPucBgyiKHRv/wZK+/BK8yj+gn9pZM8PX5fiw7jCIE8VBMfpYsYwLXmMpsFaRBdOc5JfPVS+WyVPOpKublO2BXlEOWRwSG5VUQ4EqcFEQQ=",

    //14361
    L"BwIAAACkAABSU0EyAAQAAAEAAQBDFbHe9oDceMOTO3HUD1e2390Yt8ws2keY9ReTHea2EU28ERLgp55n2i9LqRyTxVtCL5THCfdKdGVr4lZRPO2giI9phr3YnFBhocE5Y/GzDXlU/zarz3UuqYmW3RW2w5EhVFru+A2Rs086l8JU8cgEmqdZb30+3c44tlPXVZgtt/Fg7ixBfAv6Y3JsSR8FiICu8hLITDwuZFdH/Bugdb0ilVo2ElFQ2DL8ivNIKudGMoQ/rPhPN0sSKMz7D8mVmPFzGWQqty37WpU/mxU2Dxl6Cp/SrOaJbGgiFv4TtTgwzKThmG845vdHaMJ4rxyiUs+LD+Ch72tD8sif0KmVZBnCMWfqAiAsBG1HsWtEkLxP4PA18UYohGMfD9rMzEYhCoadKlguashx3ogN3QfMhS2o0sCs/GwmR1Ok68sLDD6bo58s1lEfXsq7HvysQOpxcxrLSvhluyckxkFO0S/zffl0UKFBgHLkmdhJ7IQLPLMdD1QTPfKligB+WlHge0aBhAUuZawxOfdTEXhywVKpjx5OE2AddmiMzyIwjrDBFmPigCN99awWSCuw7OHDWAzTwyQt5NEhZqlcY87oM8hT9ceBoYxoSMyHQryD4qgS5XE1BCWt6Zwo4fz7zdZBYz5MRtgQN46+Mee+682QA437GeuZiur8WGvfYrSdKC3/97wmE+THKj7GKS697bc2kiOUsklCBfo7IbXoH41xVz4SR4bdkuH3VxrHPQCAai7aLZWBWXBU8UMjxMPNnYW48fe/XUg=",

    //14342
    L"BwIAAACkAABSU0EyAAgAAAEAAQCJQzvRuG6UOAd1yRKLPxiA3bxH3uDDZPSRaR2fZEUa2/Q7qshCs+yVRLzAt+vY4hUw8TDyROB6z1c0q421+fhWXRbxIZjT4TgkRuymGLt7dOVNJ75b3876iCnSH8WVRA/q2rX6HzK4u5IkYPt0mjRz58UunmNvLRG2iDmkuKvyFxSQUy6qXK8fHdLoN31VXEBAUbdtJWZ73ePZ0yLYivAKDPr4BlQSI5WNbY5MKSiVGNfHNoODRRUhuKW5CllsYxl7j7CdaM76DjseM5KLIGLfdca5pNocIuqIV3LxzikID6J5f+0NIJsJTBj+kynC7qwaOlHDIDsyxPfVP5EzgkG0b1UWBkJOsYdiQRVFWkIR+SL2Ez0xT9NrpN3vQQ3yRdEkpiZOeHoW+X3/kP4kEf7YoHw7DAHuYY/dqGe+7KCi6q+PgTmOrjIl3haIYDmrb3Ij8XXCmq0w7/tkGXv0WHmMeAjiW8oK17l4m4YFUX2qYiKPNyKGTQLTgKnYplps2OSHKpDN8m2T87Ww0W4I7+Hwek8M1N9XfTttdpm3aAYb8FWv84QGKOJGFnHMHMHnjq8Hvl0zKKchKXOrJeppNJKvLuhzRWONM/3wn/oFlHoIeUPB11GLvmL80dGSUJYdF7h//ukouO5abspe7WJe61+l7OvshnV7PPvPhQXBMxilyR/MDRr0DbGcZDdJW0Oc7CxdG1L8Lf+Na0+J1gylP+s9EIMZbiYhunXjhYH6crBeBKmauXmRTdts3JZhTLrFfT1ofp/UeG7oi9+sbabPUROh5aw2DeO6hso+Ao5ZeWHZuP4dAQH+P9q7+WzrWCdl3QtF5lKZ56HZQyLijY4LsjojJcmhFgEODAtWKuZThE2m2Wzlrd8lMJvOeg3G8+wNSuRcpq+pge9nZMku2KJE179t7YQcsoz1ug9fRxIjys0a0379MX7HyH8AJgQPSK9nI372RD/hhS0AU1azFyQHAarV7G18zBNxsyXux2Q4icT2rMwEZ4HNZt64mRYvYgIuKZABtWV9E9SB1Jy2ZDuVX1evZuXxLYYrXhrbGyNl3Arklcl9GXeilBXJubD3r7qdUnLObHkmWOkHXAxW/APSqC8hixN/vKV4lKZmgNwrZgQ7y9JguDijDSmiRzJ4antPQAgZA3j/QgMNo6DDb/ThD5S7fHmzA994hzYRdbMoVjq0mc1O/Y4PjTm9GbMvcYi5uTx/9J6hkfBorPC7miOwr2PdGyeRXzUbW9hwTQDnjvDU07uYiAiXHpM1XdL+sXoqR0rq2cMbuiCUZA60UYmGl7LM4SsccnuearM0MkOz8+m1gHg6LEog3eVebdKuueqMd1SiORQ63biI9DebQfV6USm2LpSP++GHDgq5zPhEh34pDtAOY0kVaeVWreb/edvKchiHJ7XzOqchV7irydtNA1c0fomlG8QFIUmhMcutMudqrMBHZYMZHf3xGQw42tPbYhfMgs92E37qIzmMdFeoaWdaUtoB26LMQnVLamEj19oanJRCv4MW2TWubT7zkBH0CBc=",

    //11082
    L"BwIAAACkAABSU0EyAAgAAAEAAQANalVAnj5nONtLVceq+Xw28Vd63KajoegEJUWjdnvRZI7g29bqxmBZKwqbZxeAh7zwCEjez+syF08lPxVnajv6FAUs1wdr0lXd/J+4/Mtv8Y1l5VHHu/4N67c4CECorY6Xm/VJmpKPABkiKbJMxy2073tsg5zj2fZVyDso4MXyqBrqPHA3XVwTPSQKBR+NHb/hld3TZ17QYuW5+6nt7b749FwcjV+dKvoZSMSiVN56oPVGx6+o2wn5GNW2CHJmEHQGOumrWzg1ebqiWinRMCPQCttxS/j2uYKpFFq73Q2gp1LEt79paPUXFJD4Jv4E9caWilUU+iSc6vaZqxZzyN3aXY8Irm/jnYiCtl6jFwR2rUWX1xZbpJW2Jwoccmfrp05DDnY6cXXOXGOU5UVLb+t/8Lj94BhIh2Xj734njamY+0RMbjpwalqCIbO4ifxyRo5l3L+N/wj34EkhSCv7L/0acg5qkJYF6yt3j0witwP3pNSc86l/3FFtZJWeazrQmelxiv6v31YjAlGoVQvnL1/Wh74XFAN21xUrhWvD71uqvd1xbPkNlIgrL1alV0IUWTv3EYnbbXMsOYOvjRA1KmpiePpE0xipW+DwYKQHTDcS9C6kfSAxSS68HjHfoJMq0iFH4Iyalb9tt1Xuvor8pSFNRJpdNAEF7MUT7oT6Zkja752fkDTqcrxc6RYPUs/LuEIEAlTe6LPsf8vxJkig/kDCGzMEHISJ5wKVa+wk4HEsyvRkDh4GdAnsB+lVJttQI2nDgbwPWGD88qHm3tIEt4DaVyLU4s7tZThNcj0E2HbIdRII0v9oZkucv5x7cWmU7RPu57zBXHRKlHirDJaS3YZSAbJPB7nW39DeBrOBVqut0uo31Ate5fXmwyZRgLTMcY7LO0h6Nz5C0u+tzgiXewALBgqQdMw9pYH6X+KH95+x914PK+OWsul1SjD8rzLt6IDIDizRHQUk9azLZ2PndhQ0nwAD8oQCZhdjHkqai598LXdN0Q3aXwZnryME3FAywNHTGmew4S09GYHk4GsbsdOAdEHyFCcGFjTYWEyvY252hf1LDW6u6FXYBeG+7T1v+Zm0ZAbzLYlLdO3HQ3mXiQm2azeG9owFaQK+f9wIOOhP1dr1x97H2t56NTwE2xAOIc6tDvI2ghJ8DNqkhiaUB0P8dypzJR6ZBIss1ljTDg/r4OGlOBPOp7YM1CqKhCPYVV35GiyCZJO1DiBWJSHRKC7WnJ9toT2VgQ7vNBfx7aNEGPz/MN20h1/mPIYfeFN51mBhw6avV34m98bcspc2JFX0Np8+3ehrYtlIvaztjyWlkg/hV4ZqQOojjB2Hjl3SQ0mKT0Z7D5DDhOxAv5ub56JDL2bN8nV4RjyULMHVq6bcUh52IsXbb88i91JnAiA09jdrTmGLdVdHjPZFxchclUD8PG1fKpUmZTDc9Y1+PuO4LlVvjuhHpy9OH2jNp2VE3T2TUs0pAQspHL3CNtL/BIF1W0zDjdjHvONTIuSKfpnQ6keOSTzGXuOyCwTYSYIXVjQ=",

    //10525
    L"BwIAAACkAABSU0EyAAgAAAEAAQAnbuGx2WlyNObw/Yf56rjv3vv2Y7Vwgx92qYUHCjZ+SNC9S373NVkV9TfScPRjedLsV2CWXqPUVN256D3fvDSj7VC7exoTs4x5/2CkUGvFB+6C6lblEkkNC3nDmBoWlsoW2nRzyJH+lagckwRGv3T0+vPG3NSCsEOMfrnRpm6kvEcaK5U4ZT2QXJa1Pb09CJ0pOVn8ZtHFRMC3lRdBXlB/LAdXLcgrM7/DDTeJAcJ9mRNTT94aW40PAzZyUGtEk23373auzBOU71XIve3YxYFtCGU0mBzCo2MizjEWpf9ST4Z83eiLzIm7D9WmHOMX2xo5SMVODHKqwF2dY2tTObqiC1mbTDEdrYX6xWHiVRt/l44KTdC4yHu9tu478hDStdNr4lnf0K/ieIwNMWrDWyrL3p7oUUWDCmS55hnZctUSPclcUbpG6g0MKy2tmHmKZHj81py0DxhMg0oclp9/zxQF+LLER5MrwELEOjXqjWlgxJJ8/N/f65QCbR/XKUnw5uPVCIjksUWEOADXnq4kMjR1OGoDlQPuEyGmsk/CWOG083UeXBxrxnT8R6x1qKWHXSqP8kzRPFMVOjgh9YIoHo8E6Z/w+VqJPOnRismtwHOZ6FyZcPejXUOYCJLfq8wJl7114NSu4bUFldrix8ZaKbrU19GuAgRwrmGWQRfD9jzKtjfUPnRewBW90dNUQzwoJ3gFjc2qMVtQMkrCDs3qRSOsR4PN3DeBtYuTIUQz2Sgfh1f9qh2jj0QDrxsdBn49jE/324ws8RtDjKaPqkfqVbAlwws6CAOFkJwcxtRXCntz4ateKZpsMOmHkYMqrntMIRCqHycsMoqkm6Lqs0HTtn63EQk9NSLpaYxZymy9Ayx9lpGp6a/yXYHqPfF6xGuYpiAEN7gs+Ra5dDjzZjYUDvM+pzxR8DxwgnrQRJadoCG9+IkjNQIxKO15gWLcwKLlhlYoiqJUMyDDuBJwOPZDO1LxZaWAxfxBJtTjd67+AYUQZxHcDdPJ9U87EUK7ctpzTopUg9MmmE7d1WzIg9+h5RWSU2pK1JjP4pDnQimbkXptGx1rhdQilO58FUQcIE7oBSjeTOCmSoGoqthjnIadqa3YpwyqY2tLShrPn+IaKWi1l8NuGYpEMS9Yuh53CJoikcXXrAyIXlTQ3heAYHAs8qazhGONzpZqduFYwVzXQ8iry0l+UH17H3VN+7qXEVM/4IBXpaUyWJfHvGTxYBjSw3+zu47nXuMmo0MOMb23oN61/BICM+/Fi8VDYhketDrPGLla9J+6q5jrMrrUSz6JhW1csaKNDSDOOG+F1xAYPn3YkLdgA6i1QqyYpZghUc6IwX+YHh/S2vzghlqPoWFBVQNKdDxsiIPn2XGX1pRe1wZDgD4J5ahlzc8650AXsHSleiu0r+te+PFNyC/B6pW10e1vIv1RAJRbjFY8NvTnmi8gDK42UH1OcaFfsqI9SV94PZSyGWA5SuXo2ueFbITTb1PVl9MQzehI45Y4brRnV6Joa2is+ZqsVWG6z+tuVnii8AU=",

    //10240
    L"BwIAAACkAABSU0EyAAgAAAEAAQCNWsKi2L/3i8l2s91yX0Ea4Z5x5i9ngwB2wITlxLgCUz22U60YGehF2NeH6htxHQsqI6WEVFnxjgR5TEkWJTDrZ9Ura1wAcugczD9uz0owxYF5p8oWEku3MK7qLCPAtX+4CEKCPuruHMSZe3ieZyC/odI/50B//PBM/HEBh5FM/rVteXMDEvuMozAHqQoz3p6iDekL/Dhqy9J5foP6ZUwdEGLj2AXI4Ae6ciXy/wmM5mCtCtNq8CFV+mFSFLWFZ2sazBQ8GyyehHkMrjGQ4EG5RSQWMySiGagaWbzvZ37LR2+qqdwxOzGwQlsBRfCfmtfFnajqLZnab8A1HmlEbI7WYwHb7MoBj2FK+xowzGs5i9pIP3Brullq28R6ayAvEywixklHzarC10r2SlalORdiMJnEcPGeaJ5ZvzKG8wOATn68cLLQFKrqlrRo9XLjWrpJCTKt8CcrbRJ5ZLbYxzw4vecz2O3GyJQ8wRVCOGDq6RTaftToOE6vMqG7MjzYU9hPbxHqnWZo9c09sAh1inBJsHJi6mZZokkTZ7R8FtSrSfIGoF0Kr1BmmWZc/n9MvCBnwwlTkt0O9kkG7IJO8mrBNdGydcq+ph1MbUGib5nwWIazgcfXGXYDz1eX1RpqmhA1TkXzbwUl6vPeuncbD5kUxdGK5XueW2j9E+/Dw2zn/bWSYRVhMrSXbc77IlFRDd1tZZT5766snSQxo8+mffl6NbLimvpwh4Q7vXJULQrXxS1eGYOMq+IsH5N5vkyowkI3MHBruewkRbEyBydB9zkQuqrx3bs0lT3qB94WK72fo8QaXeVOebm9cdJQ+dMb2yGjqR2CPZOam6CLiRyCNspwVUaLfCqOnZAGa/HW7oi+2RNm/EM89kxbH2GDQl1KrIk7sZ+5BUe7dubbmE8k23LibVynY37Yn8kGooGBrCvnIuUSGebhTOWvm70S+p4jcT5dmQD5D7tRZlXccPyvRVKyUBWC5hbMZBXYd4ZVbaRQNFXVz2Thir58jpF6VIxhcCj9ifmG71qT0GFIqJsxl4pABNV42RyqefUq5Nfcw4RLRWtPtK3WTPljJXSCukRTO3jdkPelD5MZA0PLO5t95cddI9MgxIer72jM6ve1bV5fK9MbzJidJE9ZgLENvxP59Hx7rnBWAUlMlw8VTjz6MhvHMJvd7poUhxyZG21Qs/JwWQd/qsZqW7sDcg104KGNcMaHxVDVjSOisfafEX5s0zeOQghTpVEbkrScoQheL0/aNPxQvC1rsBD0K3x65vE1hl3taMw6Dps7SFr0mOGyCVCFOb2h+2eZfMvw/hvbZ3KfiwpOYJzAXgX7m0syE5v7lTtWOaHTz9BWcDXFYWX15YNjQiId/SPUuDBKki9I1YJHef2GxR2/mx1Idic6JkqeAXKDexQxEy/3Pv2tKVfJhCtmTiRTv0pDxctw1q3wXpU/lpw5q4vVlf7B9W4NDRZh3krfrd7a5UKn5Jqhc/RzvqIX05PqP8clGMM3639+0/uqrMVeG8OkAPTHC4Csvsj04QM=",

    //10158
    L"BwIAAACkAABSU0EyAAgAAAEAAQCf1EyRJa6EtwRlee0ClaLRcEhgNGS4jfVouO+MuuTnTV3avzNwgoXpQvQf4CQdsCQhBWyUUbvwbNnYG+ESsOtAiw7p7+jRrHAAR5rWRBCNeJTnKSBpz254JnjSVFMRczulrigEhSRz5bidP6SRbPK9/sKWopCND34cNNddjADibpdw7oW1g7Chb9snAjpoLv+cpSA0IWXURiT5Nz4vdQ3NPTkvH4v9MwH//JUuv19irf3QYUJSN+QkmLX65cKxxKmcUYe0/MbrxUu7KK3OM/nDpmKuKbjbUdeY4PD2uBwPQ4Ha91+bx4i7aWhqC5MYpN9PjSI+2C3mJ6uYobz5WUK/J7+MzvWOcPOgsR5RYynyZOmnD7x1cLQncA1ZgkaXkhwZXswTQGy9KRdcuZ3wIHwdzeOLbFgZu8dyj9eSuMbNPLlWFI7Ciurh1bHCMr81LiG5KWa4jy54MwD+NUkVOXbiBsjSijcfEvSFP1B4w0PPWXEf9OS9+wI5a2YZ0O0NoPLJqdbQDLlNL/bkOmdIBXs9OMEwbMZP0vhPyY19jotBsrIxQUyc5ThXr8uDzTh+J2dl03j2wpqRwykseKqp8HVjAPNYabnOSaq2/aPYIGXt6KPn/C+7xz4hyY3tTJcHK7xYAMEaJmKmqaiOR5+yO1zpevO04CYmZdFo6wRbbmrNyVu/p5dAFZyFyyglW7ieFKSgAz/isIPh+G3p8m3YF9grQ2TIQNNIN1pLJPvWvzqDIinr8gzTwzER9ZXlH9U26m8aiXptTRlXK2ws8LyVYKPqNHM9DwPJS9PuvcOykCBdeB7JvopdBU1jJUBWBsDMve0jvTWai9pujkRFsG61oclHMc1E635g+hjRxbKv7L/P2kvg5RXa6J+rpVo5jgJQ70CBgtqpNHLf6QteU8sDIlxKet1+lw7YRvfq9Wi6rmxlGqwrA9zWlCZLvnCFl8q//0a6Q+68yn5325zy67oz/X7FTWgoUU9sDDDprSwvYukrT3BlU3ntY1YAiXQtZsg6LknToQZdtj4z/bUP7sHMkds96MNRj+/+iuzEEyJaQPNGWOlzJkMa7Yujbq+5ScsxoXC5Iy8v1mi10hzYC54ByX1L9yfwi6F0rklsshl5IPSgIH+MOoZM0W+5/KlQCYeKZsIGJfyV+cVbkjLsVsFMOV+f3I+GKrJMoU8zg0vBP1SMIaEXxE5R7hd2lnzX2wIZwJvKhyHV2KSgyAQ0vpFbopB64Y1dkC/kDvEpluQ/WHjqHzwTKJyXBnFAKRNQO4BqmyNMib5N21l96Mm2nUHcxmd+KeXMuZNavvVds40FL/rOid/ROc8fK6SG/3YI+XbO4L28nPmEQPYHTfxBfkefRtUqaxC5K7QMX5LTI/ZaB+ZgJtbOXtvhUaVfyFlEzr1RBqFXXe6NhpP052qI16G7C0Sx7CT+aMv+16zqcBLb/1r4rqGhDTJjcxnkesZdc/gbDJt44RzdGo+FiZZItD3TmnyKOPjNExgA0qxdoFnwnxb5lp+qmlNi0XaOBwgSHSdiPhw=",

    //9900
    L"BwIAAACkAABSU0EyAAgAAAEAAQCb7Jceg+YeJXNdb7HHJ0irxNsGSWu7itcuEQkfS+znxm6XwxmfINt8SGzbIIka2eOB2t9L0lGwSM0uP3UPyhBzzc8FL735OL+RnimL4SVKDb5AsYpREOcNQgKsk6OOeo8q8+4+swvwfe6+VloNqCrjiE6bCS7TrC+haV+eabj1QaT+aSXNWrukmrvi1VFoQIVeet5BqHzciVV+bv3/iSG/EEkxV6Yqq4Y2o9bvSDIbE+lGc1bKPlT9zy+lYx+WMB0Nfzo7nIrKs7qCw8GbeRTsHo5GMWxrLNltFsDpoO0C62pSvxEGB/id2TwESrd7brudppjjJ+LdbCBUNam6zx2lhZmjconDvvWLYC6KXVVgTh5WHjv8z0dxkD+Hc6o6OhdXuxAA5xtZYgIah8t2ZVK5V2PEFnusqZP7fqbSUJOp6sZe3AZWWVZz6dg6VqYpDMbKBz8rhHXXHjkaqIMrmxnSmHoB4fsxelWre9oxQoQJUkASAUhflDPKtFVe30oLsN6fNwBBNVKywJogPsClqIuNiQDpsXRFg8PYBgvqDQz8DRfDpu5WyhQjdD+eVQpeczWmTyPuwfGB0TscKDhzIhSwebKK0NwCn2LunmdJEOjJsnsYLrE63rsQdcXimzPifQ5XWlV9GUqo5ce+AlX0IMmw7DSZJBe9Sr1adBFuHQvRvQ1tGyQ5oD7WxKshS8WbvKT6cZb0XBE0Ru82gl9uSvJAgOJG9E8g7BApwCfaWAMEVj/Xd8DZSjZ0VWxRlsVkhjxWeiiQWg85J08JdjC2soG14IiXRTVAGogUTcUVlOPkovrWoRVqTMLAA+Vh0R6BpcAexwUv4YVmw2661iDUmnkYWyXMcSBQP43h5SjdLirO19b/1UD9lvaCaZpyokKMD6+GNJyCX9stVuS7c1ow/nsuVDgx3Rv7wE0as5h9WSheM5p6Lzf1UTHy1Mg2XpJAn37amw7rUnOkz4qqJ5ItRwAAhRn2Cn+PUtp5Ti1vfHmPd0PodAdTUo+5lYOGmXJxx0SHTh3dSCkSIJWjoAFYnrtEWMTszcenxYlZc2e6dWNZUPO4VyftrGkF4FpWxFC63Gd15uf3vUlStFXRArMh9KQ14sf4PGmpxmoXNZBWNsa7xizW83lkS3sbtnHtLEk6xyJ01sj+HWPoEuTzSbs6v3P8NstpN37xJui+hafIA5ILpB04qlxrxIRKEow31QzrMINyiwjCnxzIrXFuEQq9aY1930q5XgYfoV8OZirdIWKYtvPWzBgEkmi5w930kqjRyA81XwhH74guWww7A1lImbygBDl5wyE8GRVg2Emy7pU2sybyvtjMLSBgmTK8h6UqEXaupvuVCYjC8BzkUGWfTG9eh50TPpFZMO4vB2l2tbfwA2oTBwvjuwaDwdUIFXYjmdti3A+EGuhvDAeGzGxZhOmQir84CYXEKMj4yaqFvaKecMCtOOwWWpAEIzRWxXJIXN6EPqiZGEauZUAXjicVI/jpkKGhWUnaLZhNFTYD6Nl/eBMA2TPj6w4AiOnr21bDjgE=",

    //9840
    L"BwIAAACkAABSU0EyAAgAAAEAAQA5WQn9lTT4Ci679UcfZW6y8GkbeGTN9bKbgjnigtWmb7pPkifbr3ihmmtJ1ZWJmZCyDyeRNHwHDieOiM8zfgRJr575RKQI8yWi6wNAZVhUZDzKlch4BgABut2lcjZRT5o/Iyotd0tKW7Np1ur8D/HawdmHXdhN42hjg7PKNfvbgXICNNK+uschVzA39HWejEowO5ppaXBObLpN28Ipun3+s0xPNePHNVKD/4azFGd11ZZWmoh3NpnZXBGW3Jk2fn6hmrQ434Mrw4qdpIfTqh/d0aWGE7CseZPYR0F9Gd6DWyXn6JzkvPBPRNtdU7SK5Xeh+pDmTnme5av3c1XNBka2hScgqAT/BOAwaIvufA6QZXccHkeHnOVO/XHEi339OT0FJLNWearerYzfHtHh6D8+d7fIdHBsgMCMd/O2suhNVBWsipzA8UPnhy4+4uPAhoV7fqaYjPbE0fUTXT82SUG11W4tjs8+kTflzwX1qoNezfLdG6++h7LJSGJNPe2QfsQlB8NxLTReIHsyW5Fv5Q0LZH/Z5tJsOeu0P39z9k/oW30TGHIVnipOkdfA1PREFFwDWJ7MKsTQkW2ikSo9Y1HbUhIAb2xI9M28GAxGxdaPa69vAepfqiPOfEFOiZcUhVkLs6vv8GVOsLRMHFalKhwNi6bWX32R76OKmRHLPPl47dkHCBy/nBVSLaVyUo25gEX3pVgGDpoiHOTzeq1qvPdguBMXHtgvpvEMTBEMDFpp1hMqWkNcapPA25oGQmJr5LouRsfaHXe52LoJpniCA/Lf7cFSCbx+Wkh1bl/4uepz45bZGpjde4WvPnKPBOsi+EZ30lYi0mfKGBQ7HS6RE9iQSbOJYZ2djnY+ok8VkGrXU28l1kQParu3mnXOcQdviIJhtH6nor3GjXYbMml40/b3lGPn6qPjf0UW9glD2apdQMyTTxO2YzLlpiW96d5SwsPTDfP83YTZUZd6Er4cvmlb7G4qidlF7xIdVzzmGx5PPAuv6oLzMf3qFHKgo8nGC3ZcHfTsHz62eTvDFfCxuqTSbZYby+SraGvez3gZSKnbmvkfaBumgMPULGjsPC0FGMf1PXzxHQ3Y5chnpxYXF86h9NRRf9efeByhj3cS1AQGNidgIfo1l0CdNDtWegcZC/0U8+0O/lMGUnemt8a+Zl6jb+XHB9czxWjfetE3KcLXlfXrIBMM7Ve3JNEU1dL01vZ7THJXYWS6mIvGnOK+nW4GxsgReW8an5HlE1qF3O0r0vmpttZ6tK0NjxZFrUIVJwE+X/rJrRIS7eJJsgLoI4HD37AMcQ3rGY4/mnR7JitqNj4TNq+P/XNNl7wkjmRLOruLrOdShKON1ZvmaZ9BKUYI02FjxRntO8MPOrR2ImdRpTp+1rGtLlWWe0MxmPOkIQIsPKocIeitjWXIgNErcdzulagizd+cmcf2PPOyNkOd7yVv1xxxLy2ePYsHdGaYxIgM0xJ+NNrNpLz9/3W2quhEt4JL6jIhnIuvIUd67SQLwf7qy2jS3lLwbkBqPJpalAE=",

    //9600
    L"BwIAAACkAABSU0EyAAgAAAEAAQD1uPI7ZDwMsPbQSyrXDZblLcBf9VNiOSYNOWsLhHkyqpipeo7uOdXrONjHU2MQLZyobpVyunYMUgmU8vaBRMJHyW+Dj0xJqb9urwYFfoExrVDQVpDOOy0kDG1cGus8utua9d64n4vwRwHM4Mtta7T4sQ/o1J9L4QYUQ9xvDc8sWSA2T47n0y3Sj4OCY0RQeQFMke6+3cdnsAYevx4wL8aRS9PKHa8ItyazQJLxmKpb8HnOJn2Ws2ycr4ClGAjT4mqaflEvZ93DWZrk2RyWos0y20NmQ7mAWrVMSSuuINExN5PcvmAuMmvU2N/sCyNa2jPlaQTjJtm0DKoADRfu+W66vTHTwyJ+P2vKQv7HtbsNZMXN0cnhxSnUlwB1C5vnYRkh3tQItJu3OR5EfbF1a3Skx9g6fhCFKbZyjNWZbVxmfn9GDYmeviJiVsp2c0Wf5qg7QT5MJZtzHFB4T+/fV9TQetBCW9LKctFclCjgrw0aaqxNUHaDBvsR/uOG7KchmsuZa7DXvCc4vo15ZSVrCD5kGYhv+PzRfT4ht8r8S/GxAaPi8gZZsQBl/iOEAdhnWwTYwyZvxgkWegQw+guYfdZzi8JZmcoFA/OTognIG2SHMBu5nM8RpBfP8MKjP7UatbGPRo5+lNx26nxiw84bLVFokSxf5JcwhMP4CTHtR7tp6jnOaVHM3ANZ/Pk9mDuo9UBoLKt6amieTK+X9fvszpLbKpp9GKlp8bb4mk96Tgs1YP4108X1fMOJNrawn67OGXhJ+MqpiPs0ORDi5ILTCdfsxb+DLuAAyp/fcWuPnZEdC/VGFL/3Ydj9yqLuk3JFvwpSVD8nI+gZdFYI/qpRV4Q5mWoqzEyzObSj4yt8Do1FL1xgDEvdSxOqmLOB9Mer1DLzzTaE3O1Is3yvPerXJN7gqgpQ69k7if1a6H23AAeEVknNj6rQof2rBrFvnkquf/4uq01jVpQqW6Pez70eYPOuLyVRrdg/X8fSrXHiWdS/df9J0jRjFleHqJy9OI7MMyUK0OTfg1ZxBc8aSEkYaZ/u5G8BKJvhhySgiQvf+j4oAuPibIvZQZ3NF90Bso9hYL8HsvPB2CiYrNzTBuIafLJ6GfHT0dxamSSzP6rW+x+LnbUersORYhx65WekmTQM1Nh8+rFRTgKLQZAS9nVnc9GZ/aZ0SIN5+wWCAFwmLcpReuEcfFBKfdnItS8426wuRKIxzC9YkrQnTQkVuOpc/IUAFoVxApqMIWZYmFFpFGm5MWUiUYlq/Pb2rEgRyYhlASYxjL4QqERC2Aq1Fi8LOQ/TfTbkqyWZQqpWVWurlnMYCf5q8B1k21JwsCYbk/waosnRvbysiCJxzk4XbQ6vBrWiDurLh1KCGeFz8XFmhoudbdAjPWyB6TgY3K9OEHmVeHRbpCosy0gCuac5N6HGAqK9H1UpqgVGOqiSFC/EyRDUSXg14d8w7CZvZEsuMgPz29LGgGx0u2pLsWTsC5XHzgqT8vfJqFHm8w+0+rf9CO70eNcrkzVqn0ubtYDPHcTzdw8=",

    // End of data
    NULL
};

BOOL set_rsa_crypto_key(WIM_INFO *esd, const WCHAR *base64_crypto_key, int key_index)
{
    DWORD crypto_key_size = sizeof(esd->crypto_key);

    if ( !CryptStringToBinaryW(base64_crypto_key, 0, CRYPT_STRING_BASE64, (BYTE *)&esd->crypto_key, &crypto_key_size, NULL, NULL) )
    {
        fwprintf(stderr, L"ERROR: Error while base64 decoding CryptoKey #%d.\n", key_index);
        return FALSE;
    }

    return TRUE;
}

BOOL open_input_file(WIM_INFO *esd, const WCHAR *esd_path)
{
    int ret = _wfopen_s(&esd->wim_file, esd_path, L"r+b");

    if ( ret != 0 )
    {
        fwprintf(stderr, L"ERROR: Cannot open input ESD image.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL check_wim_header(WIM_INFO *esd)
{
    _fseeki64(esd->wim_file, 0, SEEK_SET);

    if ( fread(&esd->hdr, WIM_HEADER_SIZE, 1, esd->wim_file) < 1 )
    {
        fwprintf(stderr, L"ERROR: Cannot read WIM header from the ESD image.\n");
        return FALSE;
    }

    if ( esd->hdr.wim_tag != WIM_TAG ||
        esd->hdr.hdr_size != WIM_HEADER_SIZE ||
        esd->hdr.wim_version != ESD_IMAGE_VERSION ||
        esd->hdr.wim_flags != ESD_IMAGE_FLAGS )
    {
        fwprintf(stderr, L"ERROR: The ESD file is not a valid encrypted image.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL get_xml_data(WIM_INFO *esd)
{
    esd->xml.offset = esd->hdr.xml_data.offset_in_wim;
    esd->xml.size = esd->hdr.xml_data.size_in_wim;

    WCHAR *xml_data = (WCHAR *)malloc((size_t)esd->xml.size + 2);

    _fseeki64(esd->wim_file, esd->xml.offset, SEEK_SET);

    if ( fread(xml_data, (size_t)esd->xml.size, 1, esd->wim_file) < 1 )
    {
        free(xml_data);
        fwprintf(stderr, L"ERROR: Cannot read embedded XML data from ESD image.\n");
        return FALSE;
    }

    xml_data[esd->xml.size >> 1] = 0;
    esd->xml.data = xml_data;

    return TRUE;
}

WCHAR *find_esd_tag(WCHAR *xml_data)
{
    WCHAR *esd_tag = wcsstr(xml_data, L"<ESD>");

    if ( esd_tag == NULL || esd_tag == xml_data )
    {
        fwprintf(stderr, L"ERROR: Cannot find <ESD> tag within the embedded XML data.\n");
        return NULL;
    }

    return esd_tag;
}

BOOL decode_session_key(WCHAR *esd_data, WIM_INFO *esd)
{
    WCHAR *key_start = wcsstr(esd_data, L"<KEY>");
    WCHAR *key_end = wcsstr(esd_data, L"</KEY>");
    SIMPLEKEYBLOB *session_key = &esd->session_key;

    if ( key_start == NULL || key_end == NULL )
    {
        fwprintf(stderr, L"ERROR: Cannot find <KEY> tag within the embedded XML data.\n");
        return FALSE;
    }

    WCHAR *base64_session_key = key_start + 5;
    DWORD key_length = key_end - base64_session_key;
    DWORD key_size = sizeof(session_key->key);

    if ( !CryptStringToBinaryW(base64_session_key, key_length, CRYPT_STRING_BASE64, (BYTE *)&session_key->key, &key_size, NULL, NULL) )
    {
        fwprintf(stderr, L"ERROR: Error while base64 decoding session key.\n");
        return FALSE;
    }

    esd->session_key_size = key_size + sizeof(session_key->hdr) + sizeof(session_key->algid);

    for ( int i = 0; i < (int)key_size >> 1; i++ )
        SWAP(BYTE, session_key->key[key_size - i - 1], session_key->key[i]);

    session_key->hdr.bType = SIMPLEBLOB;
    session_key->hdr.bVersion = CUR_BLOB_VERSION;
    session_key->hdr.reserved = 0;
    session_key->hdr.aiKeyAlg = CALG_AES_256;
    session_key->algid = CALG_RSA_KEYX;

    return TRUE;
}

BOOL get_encrypted_ranges(WCHAR *esd_data, WIM_INFO *esd)
{
    WCHAR *encrypted_tag = wcsstr(esd_data, L"<ENCRYPTED Count=\"");

    if ( encrypted_tag == NULL )
    {
        fwprintf(stderr, L"ERROR: Cannot find <ENCRYPTED> tag in the embedded XML.\n");
        return FALSE;
    }

    if ( swscanf_s(encrypted_tag, L"<ENCRYPTED Count=\"%d\">", &esd->num_encrypted_ranges) != 1 )
    {
        fwprintf(stderr, L"ERROR: Cannot get the count of encrypted ranges.\n");
        return FALSE;
    }

    esd->encrypted_ranges = (RANGE_INFO *)malloc(esd->num_encrypted_ranges * sizeof(RANGE_INFO));

    WCHAR *range_tag = wcsstr(encrypted_tag, L"<RANGE Offset=\"");
    BOOL success = TRUE;

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        if ( range_tag == NULL ||
            swscanf_s(range_tag, L"<RANGE Offset=\"%I64d\" Bytes=\"%d\">", &esd->encrypted_ranges[i].offset, &esd->encrypted_ranges[i].bytes) != 2 )
        {
            fwprintf(stderr, L"ERROR: Cannot get the encrypted range info.\n");
            success = FALSE;
            break;
        }

        range_tag = wcsstr(++range_tag, L"<RANGE Offset=\"");
    }

    return success;
}

BOOL read_embedded_xml(WIM_INFO *esd)
{
    if ( !get_xml_data(esd) )
        return FALSE;

    WCHAR *esd_data = find_esd_tag(esd->xml.data);

    if ( esd_data == NULL || !decode_session_key(esd_data, esd) )
        return FALSE;

    if ( !get_encrypted_ranges(esd_data, esd) )
        return FALSE;

    return TRUE;
}

BOOL decrypt_blocks(WIM_INFO *esd)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTKEY hPubKey = NULL;
    HCRYPTKEY hKey = NULL;

    if ( !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptImportKey(hProv, (BYTE *)&esd->crypto_key, sizeof(esd->crypto_key), 0, CRYPT_EXPORTABLE | CRYPT_OAEP, &hPubKey) ||
        !CryptImportKey(hProv, (BYTE *)&esd->session_key, esd->session_key_size, hPubKey, CRYPT_EXPORTABLE | CRYPT_OAEP, &hKey) )
    {
        if ( hPubKey != NULL )
            CryptDestroyKey(hPubKey);
        if ( hKey != NULL )
            CryptDestroyKey(hKey);
        if ( hProv != NULL )
            CryptReleaseContext(hProv, 0);

        return FALSE;
    }

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        int blocks = esd->encrypted_ranges[i].bytes >> 4;
        DWORD size = (blocks + 1) << 4;
        BYTE *data = (BYTE *)calloc(size, 1);

        _fseeki64(esd->wim_file, esd->encrypted_ranges[i].offset, SEEK_SET);
        fread(data, esd->encrypted_ranges[i].bytes, 1, esd->wim_file);
        CryptDecrypt(hKey, NULL, TRUE, 0, data, &size);

        _fseeki64(esd->wim_file, esd->encrypted_ranges[i].offset, SEEK_SET);

        fwrite(data, 16, blocks, esd->wim_file);
        fflush(esd->wim_file);

        free(data);
    }

    if ( hPubKey != NULL )
        CryptDestroyKey(hPubKey);
    if ( hKey != NULL )
        CryptDestroyKey(hKey);
    if ( hProv != NULL )
        CryptReleaseContext(hProv, 0);

    return TRUE;
}

BOOL update_integrity_info(WIM_INFO *esd, WIM_HASH_TABLE **updated_table)
{
    HCRYPTPROV hProv = NULL;
    HCRYPTHASH hHash = NULL;

    if ( !CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) )
    {
        fwprintf(stderr, L"ERROR: Error while creating hash objects.\n");

        if ( hHash != NULL )
            CryptDestroyHash(hHash);
        if ( hProv != NULL )
            CryptReleaseContext(hProv, 0);

        return FALSE;
    }

    WIM_HASH_TABLE *hash_table = (WIM_HASH_TABLE *)malloc(esd->hdr.integrity_table.size_in_wim);

    _fseeki64(esd->wim_file, esd->hdr.integrity_table.offset_in_wim, SEEK_SET);
    fread(hash_table, esd->hdr.integrity_table.size_in_wim, 1, esd->wim_file);

    ULONGLONG size_hashed = esd->hdr.lookup_table.offset_in_wim + esd->hdr.lookup_table.size_in_wim - WIM_HEADER_SIZE;
    DWORD chunk_size = hash_table->chunk_size;
    BYTE *data = (BYTE *)malloc(hash_table->chunk_size);
    DWORD bytes_read;

    for ( int i = 0; i < esd->num_encrypted_ranges; i++ )
    {
        int block_start = (int)(esd->encrypted_ranges[i].offset / chunk_size);
        int block_end = (int)((esd->encrypted_ranges[i].offset + esd->encrypted_ranges[i].bytes) / chunk_size);

        _fseeki64(esd->wim_file, block_start * chunk_size + WIM_HEADER_SIZE, SEEK_SET);

        for ( int j = block_start; j <= block_end; j++ )
        {
            if ( j == (int)(hash_table->num_elements - 1) )
                bytes_read = (DWORD)(size_hashed - (hash_table->num_elements - 1) * chunk_size);
            else
                bytes_read = chunk_size;

            fread(data, bytes_read, 1, esd->wim_file);

            HCRYPTHASH hHashDup;
            DWORD hash_size = SHA1_HASH_SIZE;

            CryptDuplicateHash(hHash, 0, 0, &hHashDup);
            CryptHashData(hHashDup, data, bytes_read, 0);
            CryptGetHashParam(hHashDup, HP_HASHVAL, hash_table->hash_list[j], &hash_size, 0);
            CryptDestroyHash(hHashDup);
        }
    }

    free(data);
    *updated_table = hash_table;

    if ( hHash != NULL )
        CryptDestroyHash(hHash);
    if ( hProv != NULL )
        CryptReleaseContext(hProv, 0);

    return TRUE;
}

BOOL update_xml_info(WIM_INFO *esd, ULONGLONG *wim_total_bytes)
{
    const WCHAR wim_tag_end[] = { L"\r\n</WIM>" };
    WCHAR *esd_tag_start = find_esd_tag(esd->xml.data);

    memcpy(esd_tag_start, wim_tag_end, sizeof(wim_tag_end));
    esd->xml.size = wcslen(esd->xml.data) << 1;

    ULONGLONG total_bytes = esd->xml.offset + esd->xml.size + esd->hdr.integrity_table.size_in_wim;
    WCHAR new_size_string[16];
    _ui64tow_s(total_bytes, new_size_string, _countof(new_size_string), 10);

    WCHAR *first_total_bytes_tag = wcsstr(esd->xml.data, L"<TOTALBYTES>");
    memcpy(first_total_bytes_tag + 12, new_size_string, wcslen(new_size_string) << 1);

    *wim_total_bytes = total_bytes;

    return TRUE;
}

BOOL update_wim_info(WIM_INFO *esd)
{
    WIM_HASH_TABLE *new_integrity_table = NULL;
    ULONGLONG total_bytes;

    if ( !update_integrity_info(esd, &new_integrity_table) ||
        !update_xml_info(esd, &total_bytes) )
    {
        return FALSE;
    }

    esd->hdr.xml_data.size_in_wim = esd->hdr.xml_data.original_size = esd->xml.size;
    _fseeki64(esd->wim_file, esd->xml.offset, SEEK_SET);
    fwrite(esd->xml.data, (size_t)esd->xml.size, 1, esd->wim_file);

    _fseeki64(esd->wim_file, esd->xml.offset + esd->xml.size, SEEK_SET);
    esd->hdr.integrity_table.offset_in_wim = _ftelli64(esd->wim_file);
    fwrite(new_integrity_table, new_integrity_table->size, 1, esd->wim_file);
    fflush(esd->wim_file);
    free(new_integrity_table);

    _fseeki64(esd->wim_file, 0, SEEK_SET);
    fwrite(&esd->hdr, WIM_HEADER_SIZE, 1, esd->wim_file);
    fflush(esd->wim_file);

    int fd = _fileno(esd->wim_file);
    _chsize_s(fd, total_bytes);

    return TRUE;
}

void cleanup_resources(WIM_INFO *esd)
{
    if ( esd->wim_file != NULL )
        fclose(esd->wim_file);

    if ( esd->xml.data != NULL )
        free(esd->xml.data);

    if ( esd->encrypted_ranges != NULL )
        free(esd->encrypted_ranges);
}

int wmain(int argc, WCHAR *argv[])
{
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);

    WIM_INFO esd;
    memset(&esd, 0, sizeof(esd));

    _wsetlocale(LC_ALL, L"");

    if ( argc < 2 || argc > 3 )
    {
        fwprintf(stderr, L"esddecrypt %s\n", VERSION);
        fwprintf(stderr, L"https://github.com/whatever127/esddecrypt\n\n");
        fwprintf(stderr, L"Original code of the decrypter by qad:\n");
        fwprintf(stderr, L"https://forums.mydigitallife.net/posts/967554\n\n");
        fwprintf(stderr, L"Usage: %s <encrypted esd> <base64 cryptokey>\n", argv[0]);
        fwprintf(stderr, L"       *** Warning ***\n");
        fwprintf(stderr, L"       The input will be directly OVERWRITTEN by the decrypted image!\n");
        return ERROR_INVALID_PARAMETER;
    }

    if ( argc == 3 )
    {
        known_base64_crypto_keys[0] = argv[2];
        known_base64_crypto_keys[1] = NULL;
    }

    BOOL success = TRUE;

    if (
        !open_input_file(&esd, argv[1]) ||
        !check_wim_header(&esd) ||
        !read_embedded_xml(&esd)
        )
    {
        cleanup_resources(&esd);
        return EXIT_FAILURE;
    }

    BOOL decryption_success = FALSE;

    for ( int i=0; known_base64_crypto_keys[i]; i++ )
    {
        if (
            !set_rsa_crypto_key(&esd, known_base64_crypto_keys[i], i) ||
            !decrypt_blocks(&esd)
            )
        {
            continue;
        }
        else
        {
            decryption_success = TRUE;
        }
    }

    if ( decryption_success )
        update_wim_info(&esd);
    else
    {
        fwprintf(stderr, L"ERROR: Decryption failed. None of the known/specified RSA key works.\n");
        success = FALSE;
    }

    cleanup_resources(&esd);
    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}

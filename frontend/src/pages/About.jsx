import { Button, Result } from 'antd';

import useLanguage from '@/locale/useLanguage';

const About = () => {
  const translate = useLanguage();
  return (
    <Result
      status="info"
      title={'IDURAR'}
      subTitle={translate('Do you need help on customize of this app')}
      extra={
        <>
          <p>
            Website : <a href="/">www.demo.com</a>{' '}
          </p>
          <p>
            GitHub :{' '}
            <a href="/">
              https://github.com/
            </a>
          </p>
          <Button
            type="primary"
            onClick={() => {
              window.open(`/`);
            }}
          >
            {translate('Contact us')}
          </Button>
        </>
      }
    />
  );
};

export default About;

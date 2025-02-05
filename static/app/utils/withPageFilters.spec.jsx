import {mountWithTheme} from 'sentry-test/enzyme';
import {act} from 'sentry-test/reactTestingLibrary';

import PageFiltersStore from 'sentry/stores/pageFiltersStore';
import withPageFilters from 'sentry/utils/withPageFilters';

describe('withPageFilters HoC', function () {
  beforeEach(() => {
    PageFiltersStore.init();
  });
  afterEach(() => {
    PageFiltersStore.reset();
  });

  it('handles projects', function () {
    const MyComponent = () => null;
    const Container = withPageFilters(MyComponent);
    const wrapper = mountWithTheme(<Container />);

    expect(wrapper.find('MyComponent').prop('selection').projects).toEqual([]);

    act(() => PageFiltersStore.updateProjects([1]));
    wrapper.update();

    expect(wrapper.find('MyComponent').prop('selection').projects).toEqual([1]);
  });

  it('handles datetime', function () {
    let selection;
    const MyComponent = () => null;
    const Container = withPageFilters(MyComponent);
    const wrapper = mountWithTheme(<Container />);

    selection = wrapper.find('MyComponent').prop('selection');
    expect(selection.datetime.period).toEqual('14d');
    expect(selection.datetime.start).toEqual(null);
    expect(selection.datetime.end).toEqual(null);

    act(() =>
      PageFiltersStore.updateDateTime({
        period: '7d',
        start: null,
        end: null,
      })
    );
    wrapper.update();

    selection = wrapper.find('MyComponent').prop('selection');
    expect(selection.datetime.period).toEqual('7d');
    expect(selection.datetime.start).toEqual(null);
    expect(selection.datetime.end).toEqual(null);

    act(() =>
      PageFiltersStore.updateDateTime({
        period: null,
        start: '2018-08-08T00:00:00',
        end: '2018-08-08T00:00:00',
      })
    );
    wrapper.update();

    selection = wrapper.find('MyComponent').prop('selection');
    expect(selection.datetime.period).toEqual(null);
    expect(selection.datetime.start).toEqual('2018-08-08T00:00:00');
    expect(selection.datetime.end).toEqual('2018-08-08T00:00:00');
  });

  it('handles environments', function () {
    const MyComponent = () => null;
    const Container = withPageFilters(MyComponent);
    const wrapper = mountWithTheme(<Container />);

    expect(wrapper.find('MyComponent').prop('selection').environments).toEqual([]);

    act(() => PageFiltersStore.updateEnvironments(['beta', 'alpha']));
    wrapper.update();

    expect(wrapper.find('MyComponent').prop('selection').environments).toEqual([
      'beta',
      'alpha',
    ]);
  });
});
